
extern "C" {
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn xmlCharInRange(val: u32, group: *const xmlChRangeGroup) -> i32;
}
pub type xmlIntFunc = unsafe extern "C" fn(i32) -> i32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlUnicodeNameTable {
    pub table: *const xmlUnicodeRange,
    pub numentries: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlUnicodeRange {
    pub rangename: *const i8,
    pub func: Option<xmlIntFunc>,
}
pub type xmlChRangeGroup = _xmlChRangeGroup;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChRangeGroup {
    pub nbShortRange: i32,
    pub nbLongRange: i32,
    pub shortRange: *const xmlChSRange,
    pub longRange: *const xmlChLRange,
}
pub type xmlChLRange = _xmlChLRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChLRange {
    pub low: u32,
    pub high: u32,
}
pub type xmlChSRange = _xmlChSRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChSRange {
    pub low: u16,
    pub high: u16,
}
static mut xmlUnicodeBlocks: [xmlUnicodeRange; 128] =  {
    [
        {
            let mut init = xmlUnicodeRange {
                rangename: b"AegeanNumbers\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsAegeanNumbers as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"AlphabeticPresentationForms\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsAlphabeticPresentationForms as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Arabic\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsArabic as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"ArabicPresentationForms-A\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsArabicPresentationFormsA as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"ArabicPresentationForms-B\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsArabicPresentationFormsB as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Armenian\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsArmenian as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Arrows\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsArrows as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"BasicLatin\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsBasicLatin as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Bengali\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsBengali as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"BlockElements\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsBlockElements as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Bopomofo\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsBopomofo as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"BopomofoExtended\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsBopomofoExtended as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"BoxDrawing\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsBoxDrawing as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"BraillePatterns\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsBraillePatterns as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Buhid\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsBuhid as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"ByzantineMusicalSymbols\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsByzantineMusicalSymbols as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKCompatibility\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCJKCompatibility as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKCompatibilityForms\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCJKCompatibilityForms as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKCompatibilityIdeographs\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCJKCompatibilityIdeographs as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKCompatibilityIdeographsSupplement\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsCJKCompatibilityIdeographsSupplement
                        as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKRadicalsSupplement\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCJKRadicalsSupplement as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKSymbolsandPunctuation\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCJKSymbolsandPunctuation as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKUnifiedIdeographs\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCJKUnifiedIdeographs as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKUnifiedIdeographsExtensionA\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsCJKUnifiedIdeographsExtensionA as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKUnifiedIdeographsExtensionB\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsCJKUnifiedIdeographsExtensionB as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Cherokee\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCherokee as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CombiningDiacriticalMarks\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCombiningDiacriticalMarks as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CombiningDiacriticalMarksforSymbols\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsCombiningDiacriticalMarksforSymbols as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CombiningHalfMarks\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCombiningHalfMarks as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CombiningMarksforSymbols\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCombiningMarksforSymbols as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"ControlPictures\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsControlPictures as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CurrencySymbols\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCurrencySymbols as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CypriotSyllabary\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCypriotSyllabary as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Cyrillic\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCyrillic as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CyrillicSupplement\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCyrillicSupplement as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Deseret\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsDeseret as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Devanagari\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsDevanagari as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Dingbats\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsDingbats as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"EnclosedAlphanumerics\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsEnclosedAlphanumerics as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"EnclosedCJKLettersandMonths\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsEnclosedCJKLettersandMonths as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Ethiopic\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsEthiopic as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"GeneralPunctuation\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsGeneralPunctuation as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"GeometricShapes\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsGeometricShapes as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Georgian\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsGeorgian as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Gothic\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsGothic as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Greek\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsGreek as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"GreekExtended\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsGreekExtended as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"GreekandCoptic\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsGreekandCoptic as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Gujarati\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsGujarati as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Gurmukhi\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsGurmukhi as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HalfwidthandFullwidthForms\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsHalfwidthandFullwidthForms as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HangulCompatibilityJamo\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsHangulCompatibilityJamo as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HangulJamo\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsHangulJamo as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HangulSyllables\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsHangulSyllables as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Hanunoo\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsHanunoo as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Hebrew\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsHebrew as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HighPrivateUseSurrogates\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsHighPrivateUseSurrogates as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HighSurrogates\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsHighSurrogates as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Hiragana\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsHiragana as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"IPAExtensions\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsIPAExtensions as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"IdeographicDescriptionCharacters\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsIdeographicDescriptionCharacters as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Kanbun\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsKanbun as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"KangxiRadicals\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsKangxiRadicals as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Kannada\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsKannada as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Katakana\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsKatakana as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"KatakanaPhoneticExtensions\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsKatakanaPhoneticExtensions as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Khmer\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsKhmer as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"KhmerSymbols\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsKhmerSymbols as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Lao\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsLao as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Latin-1Supplement\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsLatin1Supplement as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LatinExtended-A\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsLatinExtendedA as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LatinExtended-B\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsLatinExtendedB as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LatinExtendedAdditional\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsLatinExtendedAdditional as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LetterlikeSymbols\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsLetterlikeSymbols as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Limbu\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsLimbu as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LinearBIdeograms\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsLinearBIdeograms as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LinearBSyllabary\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsLinearBSyllabary as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LowSurrogates\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsLowSurrogates as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Malayalam\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsMalayalam as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MathematicalAlphanumericSymbols\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsMathematicalAlphanumericSymbols as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MathematicalOperators\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsMathematicalOperators as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MiscellaneousMathematicalSymbols-A\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsMiscellaneousMathematicalSymbolsA as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MiscellaneousMathematicalSymbols-B\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsMiscellaneousMathematicalSymbolsB as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MiscellaneousSymbols\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsMiscellaneousSymbols as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MiscellaneousSymbolsandArrows\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsMiscellaneousSymbolsandArrows as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MiscellaneousTechnical\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsMiscellaneousTechnical as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Mongolian\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsMongolian as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MusicalSymbols\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsMusicalSymbols as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Myanmar\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsMyanmar as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"NumberForms\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsNumberForms as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Ogham\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsOgham as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"OldItalic\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsOldItalic as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"OpticalCharacterRecognition\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsOpticalCharacterRecognition as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Oriya\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsOriya as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Osmanya\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsOsmanya as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"PhoneticExtensions\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsPhoneticExtensions as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"PrivateUse\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsPrivateUse as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"PrivateUseArea\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsPrivateUseArea as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Runic\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsRunic as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Shavian\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsShavian as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Sinhala\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsSinhala as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SmallFormVariants\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsSmallFormVariants as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SpacingModifierLetters\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsSpacingModifierLetters as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Specials\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsSpecials as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SuperscriptsandSubscripts\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsSuperscriptsandSubscripts as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SupplementalArrows-A\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsSupplementalArrowsA as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SupplementalArrows-B\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsSupplementalArrowsB as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SupplementalMathematicalOperators\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsSupplementalMathematicalOperators as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SupplementaryPrivateUseArea-A\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsSupplementaryPrivateUseAreaA as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SupplementaryPrivateUseArea-B\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsSupplementaryPrivateUseAreaB as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Syriac\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsSyriac as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Tagalog\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsTagalog as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Tagbanwa\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsTagbanwa as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Tags\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsTags as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"TaiLe\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsTaiLe as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"TaiXuanJingSymbols\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsTaiXuanJingSymbols as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Tamil\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsTamil as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Telugu\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsTelugu as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Thaana\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsThaana as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Thai\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsThai as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Tibetan\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsTibetan as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Ugaritic\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsUgaritic as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"UnifiedCanadianAboriginalSyllabics\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsUnifiedCanadianAboriginalSyllabics as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"VariationSelectors\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsVariationSelectors as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"VariationSelectorsSupplement\0" as *const u8 as *const i8,
                func: Some(
                    xmlUCSIsVariationSelectorsSupplement as unsafe extern "C" fn(i32) -> i32,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"YiRadicals\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsYiRadicals as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"YiSyllables\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsYiSyllables as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"YijingHexagramSymbols\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsYijingHexagramSymbols as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
    ]
};
static mut xmlUnicodeCats: [xmlUnicodeRange; 36] =  {
    [
        {
            let mut init = xmlUnicodeRange {
                rangename: b"C\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatC as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Cc\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatCc as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Cf\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatCf as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Co\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatCo as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Cs\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatCs as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"L\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatL as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Ll\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatLl as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Lm\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatLm as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Lo\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatLo as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Lt\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatLt as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Lu\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatLu as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"M\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatM as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Mc\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatMc as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Me\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatMe as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Mn\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatMn as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"N\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatN as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Nd\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatNd as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Nl\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatNl as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"No\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatNo as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"P\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatP as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Pc\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatPc as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Pd\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatPd as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Pe\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatPe as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Pf\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatPf as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Pi\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatPi as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Po\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatPo as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Ps\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatPs as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"S\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatS as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Sc\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatSc as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Sk\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatSk as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Sm\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatSm as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"So\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatSo as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Z\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatZ as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Zl\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatZl as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Zp\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatZp as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Zs\0" as *const u8 as *const i8,
                func: Some(xmlUCSIsCatZs as unsafe extern "C" fn(i32) -> i32),
            };
            init
        },
    ]
};
static mut xmlCS: [xmlChSRange; 18] = [
    {
        let mut init = _xmlChSRange {
            low: 0 as i32 as u16,
            high: 0x1f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7f as i32 as u16,
            high: 0x9f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xad as i32 as u16,
            high: 0xad as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x600 as i32 as u16,
            high: 0x603 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6dd as i32 as u16,
            high: 0x6dd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x70f as i32 as u16,
            high: 0x70f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b4 as i32 as u16,
            high: 0x17b5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x200b as i32 as u16,
            high: 0x200f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x202a as i32 as u16,
            high: 0x202e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2060 as i32 as u16,
            high: 0x2063 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x206a as i32 as u16,
            high: 0x206f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd800 as i32 as u16,
            high: 0xd800 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdb7f as i32 as u16,
            high: 0xdb80 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdbff as i32 as u16,
            high: 0xdc00 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdfff as i32 as u16,
            high: 0xe000 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf8ff as i32 as u16,
            high: 0xf8ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfeff as i32 as u16,
            high: 0xfeff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfff9 as i32 as u16,
            high: 0xfffb as i32 as u16,
        };
        init
    },
];
static mut xmlCL: [xmlChLRange; 7] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d173 as i32 as u32,
            high: 0x1d17a as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0001 as i32 as u32,
            high: 0xe0001 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0020 as i32 as u32,
            high: 0xe007f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xf0000 as i32 as u32,
            high: 0xf0000 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xffffd as i32 as u32,
            high: 0xffffd as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x100000 as i32 as u32,
            high: 0x100000 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10fffd as i32 as u32,
            high: 0x10fffd as i32 as u32,
        };
        init
    },
];
static mut xmlCG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 18 as i32,
            nbLongRange: 7 as i32,
            shortRange: xmlCS.as_ptr(),
            longRange: xmlCL.as_ptr(),
        };
        init
    }
};
static mut xmlCfS: [xmlChSRange; 11] = [
    {
        let mut init = _xmlChSRange {
            low: 0xad as i32 as u16,
            high: 0xad as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x600 as i32 as u16,
            high: 0x603 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6dd as i32 as u16,
            high: 0x6dd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x70f as i32 as u16,
            high: 0x70f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b4 as i32 as u16,
            high: 0x17b5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x200b as i32 as u16,
            high: 0x200f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x202a as i32 as u16,
            high: 0x202e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2060 as i32 as u16,
            high: 0x2063 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x206a as i32 as u16,
            high: 0x206f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfeff as i32 as u16,
            high: 0xfeff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfff9 as i32 as u16,
            high: 0xfffb as i32 as u16,
        };
        init
    },
];
static mut xmlCfL: [xmlChLRange; 3] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d173 as i32 as u32,
            high: 0x1d17a as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0001 as i32 as u32,
            high: 0xe0001 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0020 as i32 as u32,
            high: 0xe007f as i32 as u32,
        };
        init
    },
];
static mut xmlCfG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 11 as i32,
            nbLongRange: 3 as i32,
            shortRange: xmlCfS.as_ptr(),
            longRange: xmlCfL.as_ptr(),
        };
        init
    }
};
static mut xmlLS: [xmlChSRange; 279] = [
    {
        let mut init = _xmlChSRange {
            low: 0x41 as i32 as u16,
            high: 0x5a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x61 as i32 as u16,
            high: 0x7a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaa as i32 as u16,
            high: 0xaa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5 as i32 as u16,
            high: 0xb5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba as i32 as u16,
            high: 0xba as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc0 as i32 as u16,
            high: 0xd6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd8 as i32 as u16,
            high: 0xf6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf8 as i32 as u16,
            high: 0x236 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x250 as i32 as u16,
            high: 0x2c1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c6 as i32 as u16,
            high: 0x2d1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e0 as i32 as u16,
            high: 0x2e4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ee as i32 as u16,
            high: 0x2ee as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x37a as i32 as u16,
            high: 0x37a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x386 as i32 as u16,
            high: 0x386 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x388 as i32 as u16,
            high: 0x38a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x38c as i32 as u16,
            high: 0x38c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x38e as i32 as u16,
            high: 0x3a1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3a3 as i32 as u16,
            high: 0x3ce as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d0 as i32 as u16,
            high: 0x3f5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f7 as i32 as u16,
            high: 0x3fb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x400 as i32 as u16,
            high: 0x481 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48a as i32 as u16,
            high: 0x4ce as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d0 as i32 as u16,
            high: 0x4f5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f8 as i32 as u16,
            high: 0x4f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x500 as i32 as u16,
            high: 0x50f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x531 as i32 as u16,
            high: 0x556 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x559 as i32 as u16,
            high: 0x559 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x561 as i32 as u16,
            high: 0x587 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5d0 as i32 as u16,
            high: 0x5ea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5f0 as i32 as u16,
            high: 0x5f2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x621 as i32 as u16,
            high: 0x63a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x640 as i32 as u16,
            high: 0x64a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x66e as i32 as u16,
            high: 0x66f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x671 as i32 as u16,
            high: 0x6d3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d5 as i32 as u16,
            high: 0x6d5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e5 as i32 as u16,
            high: 0x6e6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ee as i32 as u16,
            high: 0x6ef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6fa as i32 as u16,
            high: 0x6fc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ff as i32 as u16,
            high: 0x6ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x710 as i32 as u16,
            high: 0x710 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x712 as i32 as u16,
            high: 0x72f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x74d as i32 as u16,
            high: 0x74f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x780 as i32 as u16,
            high: 0x7a5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7b1 as i32 as u16,
            high: 0x7b1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x904 as i32 as u16,
            high: 0x939 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93d as i32 as u16,
            high: 0x93d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x950 as i32 as u16,
            high: 0x950 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x958 as i32 as u16,
            high: 0x961 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x985 as i32 as u16,
            high: 0x98c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x98f as i32 as u16,
            high: 0x990 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x993 as i32 as u16,
            high: 0x9a8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9aa as i32 as u16,
            high: 0x9b0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9b2 as i32 as u16,
            high: 0x9b2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9b6 as i32 as u16,
            high: 0x9b9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9bd as i32 as u16,
            high: 0x9bd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9dc as i32 as u16,
            high: 0x9dd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9df as i32 as u16,
            high: 0x9e1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f0 as i32 as u16,
            high: 0x9f1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa05 as i32 as u16,
            high: 0xa0a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa0f as i32 as u16,
            high: 0xa10 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa13 as i32 as u16,
            high: 0xa28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa2a as i32 as u16,
            high: 0xa30 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa32 as i32 as u16,
            high: 0xa33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa35 as i32 as u16,
            high: 0xa36 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa38 as i32 as u16,
            high: 0xa39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa59 as i32 as u16,
            high: 0xa5c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa5e as i32 as u16,
            high: 0xa5e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa72 as i32 as u16,
            high: 0xa74 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa85 as i32 as u16,
            high: 0xa8d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa8f as i32 as u16,
            high: 0xa91 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa93 as i32 as u16,
            high: 0xaa8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaaa as i32 as u16,
            high: 0xab0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xab2 as i32 as u16,
            high: 0xab3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xab5 as i32 as u16,
            high: 0xab9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabd as i32 as u16,
            high: 0xabd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xad0 as i32 as u16,
            high: 0xad0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae0 as i32 as u16,
            high: 0xae1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb05 as i32 as u16,
            high: 0xb0c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb0f as i32 as u16,
            high: 0xb10 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb13 as i32 as u16,
            high: 0xb28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb2a as i32 as u16,
            high: 0xb30 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb32 as i32 as u16,
            high: 0xb33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb35 as i32 as u16,
            high: 0xb39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3d as i32 as u16,
            high: 0xb3d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5c as i32 as u16,
            high: 0xb5d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5f as i32 as u16,
            high: 0xb61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb71 as i32 as u16,
            high: 0xb71 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb83 as i32 as u16,
            high: 0xb83 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb85 as i32 as u16,
            high: 0xb8a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb8e as i32 as u16,
            high: 0xb90 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb92 as i32 as u16,
            high: 0xb95 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb99 as i32 as u16,
            high: 0xb9a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9c as i32 as u16,
            high: 0xb9c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9e as i32 as u16,
            high: 0xb9f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba3 as i32 as u16,
            high: 0xba4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba8 as i32 as u16,
            high: 0xbaa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbae as i32 as u16,
            high: 0xbb5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbb7 as i32 as u16,
            high: 0xbb9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc05 as i32 as u16,
            high: 0xc0c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc0e as i32 as u16,
            high: 0xc10 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc12 as i32 as u16,
            high: 0xc28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc2a as i32 as u16,
            high: 0xc33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc35 as i32 as u16,
            high: 0xc39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc60 as i32 as u16,
            high: 0xc61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc85 as i32 as u16,
            high: 0xc8c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc8e as i32 as u16,
            high: 0xc90 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc92 as i32 as u16,
            high: 0xca8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcaa as i32 as u16,
            high: 0xcb3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcb5 as i32 as u16,
            high: 0xcb9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbd as i32 as u16,
            high: 0xcbd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcde as i32 as u16,
            high: 0xcde as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xce0 as i32 as u16,
            high: 0xce1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd05 as i32 as u16,
            high: 0xd0c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd0e as i32 as u16,
            high: 0xd10 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd12 as i32 as u16,
            high: 0xd28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd2a as i32 as u16,
            high: 0xd39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd60 as i32 as u16,
            high: 0xd61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd85 as i32 as u16,
            high: 0xd96 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd9a as i32 as u16,
            high: 0xdb1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdb3 as i32 as u16,
            high: 0xdbb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdbd as i32 as u16,
            high: 0xdbd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdc0 as i32 as u16,
            high: 0xdc6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe01 as i32 as u16,
            high: 0xe30 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe32 as i32 as u16,
            high: 0xe33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe40 as i32 as u16,
            high: 0xe46 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe81 as i32 as u16,
            high: 0xe82 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe84 as i32 as u16,
            high: 0xe84 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe87 as i32 as u16,
            high: 0xe88 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe8a as i32 as u16,
            high: 0xe8a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe8d as i32 as u16,
            high: 0xe8d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe94 as i32 as u16,
            high: 0xe97 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe99 as i32 as u16,
            high: 0xe9f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea1 as i32 as u16,
            high: 0xea3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea5 as i32 as u16,
            high: 0xea5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea7 as i32 as u16,
            high: 0xea7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeaa as i32 as u16,
            high: 0xeab as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xead as i32 as u16,
            high: 0xeb0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb2 as i32 as u16,
            high: 0xeb3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xebd as i32 as u16,
            high: 0xebd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec0 as i32 as u16,
            high: 0xec4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec6 as i32 as u16,
            high: 0xec6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xedc as i32 as u16,
            high: 0xedd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf00 as i32 as u16,
            high: 0xf00 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf40 as i32 as u16,
            high: 0xf47 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf49 as i32 as u16,
            high: 0xf6a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf88 as i32 as u16,
            high: 0xf8b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1000 as i32 as u16,
            high: 0x1021 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1023 as i32 as u16,
            high: 0x1027 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1029 as i32 as u16,
            high: 0x102a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1050 as i32 as u16,
            high: 0x1055 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10a0 as i32 as u16,
            high: 0x10c5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10d0 as i32 as u16,
            high: 0x10f8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1100 as i32 as u16,
            high: 0x1159 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x115f as i32 as u16,
            high: 0x11a2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11a8 as i32 as u16,
            high: 0x11f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1200 as i32 as u16,
            high: 0x1206 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1208 as i32 as u16,
            high: 0x1246 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1248 as i32 as u16,
            high: 0x1248 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x124a as i32 as u16,
            high: 0x124d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1250 as i32 as u16,
            high: 0x1256 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1258 as i32 as u16,
            high: 0x1258 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x125a as i32 as u16,
            high: 0x125d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1260 as i32 as u16,
            high: 0x1286 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1288 as i32 as u16,
            high: 0x1288 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x128a as i32 as u16,
            high: 0x128d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1290 as i32 as u16,
            high: 0x12ae as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b0 as i32 as u16,
            high: 0x12b0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b2 as i32 as u16,
            high: 0x12b5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b8 as i32 as u16,
            high: 0x12be as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c0 as i32 as u16,
            high: 0x12c0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c2 as i32 as u16,
            high: 0x12c5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c8 as i32 as u16,
            high: 0x12ce as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12d0 as i32 as u16,
            high: 0x12d6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12d8 as i32 as u16,
            high: 0x12ee as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12f0 as i32 as u16,
            high: 0x130e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1310 as i32 as u16,
            high: 0x1310 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1312 as i32 as u16,
            high: 0x1315 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1318 as i32 as u16,
            high: 0x131e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1320 as i32 as u16,
            high: 0x1346 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1348 as i32 as u16,
            high: 0x135a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13a0 as i32 as u16,
            high: 0x13f4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1401 as i32 as u16,
            high: 0x166c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x166f as i32 as u16,
            high: 0x1676 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1681 as i32 as u16,
            high: 0x169a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16a0 as i32 as u16,
            high: 0x16ea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1700 as i32 as u16,
            high: 0x170c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x170e as i32 as u16,
            high: 0x1711 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1720 as i32 as u16,
            high: 0x1731 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1740 as i32 as u16,
            high: 0x1751 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1760 as i32 as u16,
            high: 0x176c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x176e as i32 as u16,
            high: 0x1770 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1780 as i32 as u16,
            high: 0x17b3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d7 as i32 as u16,
            high: 0x17d7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17dc as i32 as u16,
            high: 0x17dc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1820 as i32 as u16,
            high: 0x1877 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1880 as i32 as u16,
            high: 0x18a8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1900 as i32 as u16,
            high: 0x191c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1950 as i32 as u16,
            high: 0x196d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1970 as i32 as u16,
            high: 0x1974 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d00 as i32 as u16,
            high: 0x1d6b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e00 as i32 as u16,
            high: 0x1e9b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea0 as i32 as u16,
            high: 0x1ef9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f00 as i32 as u16,
            high: 0x1f15 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f18 as i32 as u16,
            high: 0x1f1d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f20 as i32 as u16,
            high: 0x1f45 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f48 as i32 as u16,
            high: 0x1f4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f50 as i32 as u16,
            high: 0x1f57 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f59 as i32 as u16,
            high: 0x1f59 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5b as i32 as u16,
            high: 0x1f5b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5d as i32 as u16,
            high: 0x1f5d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5f as i32 as u16,
            high: 0x1f7d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f80 as i32 as u16,
            high: 0x1fb4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fb6 as i32 as u16,
            high: 0x1fbc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbe as i32 as u16,
            high: 0x1fbe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc2 as i32 as u16,
            high: 0x1fc4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc6 as i32 as u16,
            high: 0x1fcc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd0 as i32 as u16,
            high: 0x1fd3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd6 as i32 as u16,
            high: 0x1fdb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fe0 as i32 as u16,
            high: 0x1fec as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff2 as i32 as u16,
            high: 0x1ff4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff6 as i32 as u16,
            high: 0x1ffc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2071 as i32 as u16,
            high: 0x2071 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207f as i32 as u16,
            high: 0x207f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2102 as i32 as u16,
            high: 0x2102 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2107 as i32 as u16,
            high: 0x2107 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x210a as i32 as u16,
            high: 0x2113 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2115 as i32 as u16,
            high: 0x2115 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2119 as i32 as u16,
            high: 0x211d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2124 as i32 as u16,
            high: 0x2124 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2126 as i32 as u16,
            high: 0x2126 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2128 as i32 as u16,
            high: 0x2128 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212a as i32 as u16,
            high: 0x212d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212f as i32 as u16,
            high: 0x2131 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2133 as i32 as u16,
            high: 0x2139 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213d as i32 as u16,
            high: 0x213f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2145 as i32 as u16,
            high: 0x2149 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3005 as i32 as u16,
            high: 0x3006 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3031 as i32 as u16,
            high: 0x3035 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303b as i32 as u16,
            high: 0x303c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3041 as i32 as u16,
            high: 0x3096 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309d as i32 as u16,
            high: 0x309f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30a1 as i32 as u16,
            high: 0x30fa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30fc as i32 as u16,
            high: 0x30ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3105 as i32 as u16,
            high: 0x312c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3131 as i32 as u16,
            high: 0x318e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x31a0 as i32 as u16,
            high: 0x31b7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x31f0 as i32 as u16,
            high: 0x31ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3400 as i32 as u16,
            high: 0x3400 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4db5 as i32 as u16,
            high: 0x4db5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e00 as i32 as u16,
            high: 0x4e00 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9fa5 as i32 as u16,
            high: 0x9fa5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa000 as i32 as u16,
            high: 0xa48c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac00 as i32 as u16,
            high: 0xac00 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd7a3 as i32 as u16,
            high: 0xd7a3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf900 as i32 as u16,
            high: 0xfa2d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfa30 as i32 as u16,
            high: 0xfa6a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb00 as i32 as u16,
            high: 0xfb06 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb13 as i32 as u16,
            high: 0xfb17 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1d as i32 as u16,
            high: 0xfb1d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1f as i32 as u16,
            high: 0xfb28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb2a as i32 as u16,
            high: 0xfb36 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb38 as i32 as u16,
            high: 0xfb3c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb3e as i32 as u16,
            high: 0xfb3e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb40 as i32 as u16,
            high: 0xfb41 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb43 as i32 as u16,
            high: 0xfb44 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb46 as i32 as u16,
            high: 0xfbb1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfbd3 as i32 as u16,
            high: 0xfd3d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd50 as i32 as u16,
            high: 0xfd8f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd92 as i32 as u16,
            high: 0xfdc7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfdf0 as i32 as u16,
            high: 0xfdfb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe70 as i32 as u16,
            high: 0xfe74 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe76 as i32 as u16,
            high: 0xfefc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff21 as i32 as u16,
            high: 0xff3a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff41 as i32 as u16,
            high: 0xff5a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff66 as i32 as u16,
            high: 0xffbe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffc2 as i32 as u16,
            high: 0xffc7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffca as i32 as u16,
            high: 0xffcf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffd2 as i32 as u16,
            high: 0xffd7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffda as i32 as u16,
            high: 0xffdc as i32 as u16,
        };
        init
    },
];
static mut xmlLL: [xmlChLRange; 50] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10000 as i32 as u32,
            high: 0x1000b as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1000d as i32 as u32,
            high: 0x10026 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10028 as i32 as u32,
            high: 0x1003a as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1003c as i32 as u32,
            high: 0x1003d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1003f as i32 as u32,
            high: 0x1004d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10050 as i32 as u32,
            high: 0x1005d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10080 as i32 as u32,
            high: 0x100fa as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10300 as i32 as u32,
            high: 0x1031e as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10330 as i32 as u32,
            high: 0x10349 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10380 as i32 as u32,
            high: 0x1039d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10400 as i32 as u32,
            high: 0x1049d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10800 as i32 as u32,
            high: 0x10805 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10808 as i32 as u32,
            high: 0x10808 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1080a as i32 as u32,
            high: 0x10835 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10837 as i32 as u32,
            high: 0x10838 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1083c as i32 as u32,
            high: 0x1083c as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1083f as i32 as u32,
            high: 0x1083f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d400 as i32 as u32,
            high: 0x1d454 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d456 as i32 as u32,
            high: 0x1d49c as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d49e as i32 as u32,
            high: 0x1d49f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a2 as i32 as u32,
            high: 0x1d4a2 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a5 as i32 as u32,
            high: 0x1d4a6 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a9 as i32 as u32,
            high: 0x1d4ac as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4ae as i32 as u32,
            high: 0x1d4b9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4bb as i32 as u32,
            high: 0x1d4bb as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4bd as i32 as u32,
            high: 0x1d4c3 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4c5 as i32 as u32,
            high: 0x1d505 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d507 as i32 as u32,
            high: 0x1d50a as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d50d as i32 as u32,
            high: 0x1d514 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d516 as i32 as u32,
            high: 0x1d51c as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d51e as i32 as u32,
            high: 0x1d539 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d53b as i32 as u32,
            high: 0x1d53e as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d540 as i32 as u32,
            high: 0x1d544 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d546 as i32 as u32,
            high: 0x1d546 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d54a as i32 as u32,
            high: 0x1d550 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d552 as i32 as u32,
            high: 0x1d6a3 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6a8 as i32 as u32,
            high: 0x1d6c0 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6c2 as i32 as u32,
            high: 0x1d6da as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6dc as i32 as u32,
            high: 0x1d6fa as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6fc as i32 as u32,
            high: 0x1d714 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d716 as i32 as u32,
            high: 0x1d734 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d736 as i32 as u32,
            high: 0x1d74e as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d750 as i32 as u32,
            high: 0x1d76e as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d770 as i32 as u32,
            high: 0x1d788 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d78a as i32 as u32,
            high: 0x1d7a8 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7aa as i32 as u32,
            high: 0x1d7c2 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7c4 as i32 as u32,
            high: 0x1d7c9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x20000 as i32 as u32,
            high: 0x20000 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x2a6d6 as i32 as u32,
            high: 0x2a6d6 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x2f800 as i32 as u32,
            high: 0x2fa1d as i32 as u32,
        };
        init
    },
];
static mut xmlLG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 279 as i32,
            nbLongRange: 50 as i32,
            shortRange: xmlLS.as_ptr(),
            longRange: xmlLL.as_ptr(),
        };
        init
    }
};
static mut xmlLlS: [xmlChSRange; 396] = [
    {
        let mut init = _xmlChSRange {
            low: 0x61 as i32 as u16,
            high: 0x7a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaa as i32 as u16,
            high: 0xaa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5 as i32 as u16,
            high: 0xb5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba as i32 as u16,
            high: 0xba as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdf as i32 as u16,
            high: 0xf6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf8 as i32 as u16,
            high: 0xff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x101 as i32 as u16,
            high: 0x101 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x103 as i32 as u16,
            high: 0x103 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x105 as i32 as u16,
            high: 0x105 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x107 as i32 as u16,
            high: 0x107 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x109 as i32 as u16,
            high: 0x109 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10b as i32 as u16,
            high: 0x10b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10d as i32 as u16,
            high: 0x10d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10f as i32 as u16,
            high: 0x10f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x111 as i32 as u16,
            high: 0x111 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x113 as i32 as u16,
            high: 0x113 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x115 as i32 as u16,
            high: 0x115 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x117 as i32 as u16,
            high: 0x117 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x119 as i32 as u16,
            high: 0x119 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11b as i32 as u16,
            high: 0x11b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11d as i32 as u16,
            high: 0x11d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11f as i32 as u16,
            high: 0x11f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x121 as i32 as u16,
            high: 0x121 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x123 as i32 as u16,
            high: 0x123 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x125 as i32 as u16,
            high: 0x125 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x127 as i32 as u16,
            high: 0x127 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x129 as i32 as u16,
            high: 0x129 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b as i32 as u16,
            high: 0x12b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12d as i32 as u16,
            high: 0x12d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12f as i32 as u16,
            high: 0x12f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x131 as i32 as u16,
            high: 0x131 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x133 as i32 as u16,
            high: 0x133 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x135 as i32 as u16,
            high: 0x135 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x137 as i32 as u16,
            high: 0x138 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13a as i32 as u16,
            high: 0x13a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13c as i32 as u16,
            high: 0x13c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13e as i32 as u16,
            high: 0x13e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x140 as i32 as u16,
            high: 0x140 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x142 as i32 as u16,
            high: 0x142 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x144 as i32 as u16,
            high: 0x144 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x146 as i32 as u16,
            high: 0x146 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x148 as i32 as u16,
            high: 0x149 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14b as i32 as u16,
            high: 0x14b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14d as i32 as u16,
            high: 0x14d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14f as i32 as u16,
            high: 0x14f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x151 as i32 as u16,
            high: 0x151 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x153 as i32 as u16,
            high: 0x153 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x155 as i32 as u16,
            high: 0x155 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x157 as i32 as u16,
            high: 0x157 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x159 as i32 as u16,
            high: 0x159 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15b as i32 as u16,
            high: 0x15b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15d as i32 as u16,
            high: 0x15d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15f as i32 as u16,
            high: 0x15f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x161 as i32 as u16,
            high: 0x161 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x163 as i32 as u16,
            high: 0x163 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x165 as i32 as u16,
            high: 0x165 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x167 as i32 as u16,
            high: 0x167 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x169 as i32 as u16,
            high: 0x169 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16b as i32 as u16,
            high: 0x16b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16d as i32 as u16,
            high: 0x16d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16f as i32 as u16,
            high: 0x16f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x171 as i32 as u16,
            high: 0x171 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x173 as i32 as u16,
            high: 0x173 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x175 as i32 as u16,
            high: 0x175 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x177 as i32 as u16,
            high: 0x177 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17a as i32 as u16,
            high: 0x17a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17c as i32 as u16,
            high: 0x17c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17e as i32 as u16,
            high: 0x180 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x183 as i32 as u16,
            high: 0x183 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x185 as i32 as u16,
            high: 0x185 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x188 as i32 as u16,
            high: 0x188 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x18c as i32 as u16,
            high: 0x18d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x192 as i32 as u16,
            high: 0x192 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x195 as i32 as u16,
            high: 0x195 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x199 as i32 as u16,
            high: 0x19b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x19e as i32 as u16,
            high: 0x19e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a1 as i32 as u16,
            high: 0x1a1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a3 as i32 as u16,
            high: 0x1a3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a5 as i32 as u16,
            high: 0x1a5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a8 as i32 as u16,
            high: 0x1a8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1aa as i32 as u16,
            high: 0x1ab as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ad as i32 as u16,
            high: 0x1ad as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b0 as i32 as u16,
            high: 0x1b0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b4 as i32 as u16,
            high: 0x1b4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b6 as i32 as u16,
            high: 0x1b6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b9 as i32 as u16,
            high: 0x1ba as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1bd as i32 as u16,
            high: 0x1bf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c6 as i32 as u16,
            high: 0x1c6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c9 as i32 as u16,
            high: 0x1c9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1cc as i32 as u16,
            high: 0x1cc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ce as i32 as u16,
            high: 0x1ce as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d0 as i32 as u16,
            high: 0x1d0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d2 as i32 as u16,
            high: 0x1d2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d4 as i32 as u16,
            high: 0x1d4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d6 as i32 as u16,
            high: 0x1d6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d8 as i32 as u16,
            high: 0x1d8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1da as i32 as u16,
            high: 0x1da as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1dc as i32 as u16,
            high: 0x1dd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1df as i32 as u16,
            high: 0x1df as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1 as i32 as u16,
            high: 0x1e1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3 as i32 as u16,
            high: 0x1e3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5 as i32 as u16,
            high: 0x1e5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7 as i32 as u16,
            high: 0x1e7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e9 as i32 as u16,
            high: 0x1e9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb as i32 as u16,
            high: 0x1eb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed as i32 as u16,
            high: 0x1ed as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef as i32 as u16,
            high: 0x1f0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f3 as i32 as u16,
            high: 0x1f3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5 as i32 as u16,
            high: 0x1f5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f9 as i32 as u16,
            high: 0x1f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fb as i32 as u16,
            high: 0x1fb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd as i32 as u16,
            high: 0x1fd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff as i32 as u16,
            high: 0x1ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x201 as i32 as u16,
            high: 0x201 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x203 as i32 as u16,
            high: 0x203 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x205 as i32 as u16,
            high: 0x205 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207 as i32 as u16,
            high: 0x207 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x209 as i32 as u16,
            high: 0x209 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20b as i32 as u16,
            high: 0x20b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20d as i32 as u16,
            high: 0x20d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20f as i32 as u16,
            high: 0x20f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x211 as i32 as u16,
            high: 0x211 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213 as i32 as u16,
            high: 0x213 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x215 as i32 as u16,
            high: 0x215 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x217 as i32 as u16,
            high: 0x217 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x219 as i32 as u16,
            high: 0x219 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21b as i32 as u16,
            high: 0x21b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d as i32 as u16,
            high: 0x21d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21f as i32 as u16,
            high: 0x21f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x221 as i32 as u16,
            high: 0x221 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x223 as i32 as u16,
            high: 0x223 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x225 as i32 as u16,
            high: 0x225 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x227 as i32 as u16,
            high: 0x227 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x229 as i32 as u16,
            high: 0x229 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22b as i32 as u16,
            high: 0x22b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22d as i32 as u16,
            high: 0x22d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22f as i32 as u16,
            high: 0x22f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x231 as i32 as u16,
            high: 0x231 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x233 as i32 as u16,
            high: 0x236 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x250 as i32 as u16,
            high: 0x2af as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x390 as i32 as u16,
            high: 0x390 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ac as i32 as u16,
            high: 0x3ce as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d0 as i32 as u16,
            high: 0x3d1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d5 as i32 as u16,
            high: 0x3d7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d9 as i32 as u16,
            high: 0x3d9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3db as i32 as u16,
            high: 0x3db as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3dd as i32 as u16,
            high: 0x3dd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3df as i32 as u16,
            high: 0x3df as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e1 as i32 as u16,
            high: 0x3e1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e3 as i32 as u16,
            high: 0x3e3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e5 as i32 as u16,
            high: 0x3e5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e7 as i32 as u16,
            high: 0x3e7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e9 as i32 as u16,
            high: 0x3e9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3eb as i32 as u16,
            high: 0x3eb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ed as i32 as u16,
            high: 0x3ed as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ef as i32 as u16,
            high: 0x3f3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f5 as i32 as u16,
            high: 0x3f5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f8 as i32 as u16,
            high: 0x3f8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3fb as i32 as u16,
            high: 0x3fb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x430 as i32 as u16,
            high: 0x45f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x461 as i32 as u16,
            high: 0x461 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x463 as i32 as u16,
            high: 0x463 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x465 as i32 as u16,
            high: 0x465 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x467 as i32 as u16,
            high: 0x467 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x469 as i32 as u16,
            high: 0x469 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46b as i32 as u16,
            high: 0x46b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46d as i32 as u16,
            high: 0x46d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46f as i32 as u16,
            high: 0x46f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x471 as i32 as u16,
            high: 0x471 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x473 as i32 as u16,
            high: 0x473 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x475 as i32 as u16,
            high: 0x475 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x477 as i32 as u16,
            high: 0x477 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x479 as i32 as u16,
            high: 0x479 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47b as i32 as u16,
            high: 0x47b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47d as i32 as u16,
            high: 0x47d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47f as i32 as u16,
            high: 0x47f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x481 as i32 as u16,
            high: 0x481 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48b as i32 as u16,
            high: 0x48b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48d as i32 as u16,
            high: 0x48d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48f as i32 as u16,
            high: 0x48f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x491 as i32 as u16,
            high: 0x491 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x493 as i32 as u16,
            high: 0x493 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x495 as i32 as u16,
            high: 0x495 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x497 as i32 as u16,
            high: 0x497 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x499 as i32 as u16,
            high: 0x499 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49b as i32 as u16,
            high: 0x49b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49d as i32 as u16,
            high: 0x49d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49f as i32 as u16,
            high: 0x49f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a1 as i32 as u16,
            high: 0x4a1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a3 as i32 as u16,
            high: 0x4a3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a5 as i32 as u16,
            high: 0x4a5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a7 as i32 as u16,
            high: 0x4a7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a9 as i32 as u16,
            high: 0x4a9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ab as i32 as u16,
            high: 0x4ab as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ad as i32 as u16,
            high: 0x4ad as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4af as i32 as u16,
            high: 0x4af as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b1 as i32 as u16,
            high: 0x4b1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b3 as i32 as u16,
            high: 0x4b3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b5 as i32 as u16,
            high: 0x4b5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b7 as i32 as u16,
            high: 0x4b7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b9 as i32 as u16,
            high: 0x4b9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4bb as i32 as u16,
            high: 0x4bb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4bd as i32 as u16,
            high: 0x4bd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4bf as i32 as u16,
            high: 0x4bf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c2 as i32 as u16,
            high: 0x4c2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c4 as i32 as u16,
            high: 0x4c4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c6 as i32 as u16,
            high: 0x4c6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c8 as i32 as u16,
            high: 0x4c8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ca as i32 as u16,
            high: 0x4ca as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4cc as i32 as u16,
            high: 0x4cc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ce as i32 as u16,
            high: 0x4ce as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d1 as i32 as u16,
            high: 0x4d1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d3 as i32 as u16,
            high: 0x4d3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d5 as i32 as u16,
            high: 0x4d5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d7 as i32 as u16,
            high: 0x4d7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d9 as i32 as u16,
            high: 0x4d9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4db as i32 as u16,
            high: 0x4db as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4dd as i32 as u16,
            high: 0x4dd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4df as i32 as u16,
            high: 0x4df as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e1 as i32 as u16,
            high: 0x4e1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e3 as i32 as u16,
            high: 0x4e3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e5 as i32 as u16,
            high: 0x4e5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e7 as i32 as u16,
            high: 0x4e7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e9 as i32 as u16,
            high: 0x4e9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4eb as i32 as u16,
            high: 0x4eb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ed as i32 as u16,
            high: 0x4ed as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ef as i32 as u16,
            high: 0x4ef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f1 as i32 as u16,
            high: 0x4f1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f3 as i32 as u16,
            high: 0x4f3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f5 as i32 as u16,
            high: 0x4f5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f9 as i32 as u16,
            high: 0x4f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x501 as i32 as u16,
            high: 0x501 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x503 as i32 as u16,
            high: 0x503 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x505 as i32 as u16,
            high: 0x505 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x507 as i32 as u16,
            high: 0x507 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x509 as i32 as u16,
            high: 0x509 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50b as i32 as u16,
            high: 0x50b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50d as i32 as u16,
            high: 0x50d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50f as i32 as u16,
            high: 0x50f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x561 as i32 as u16,
            high: 0x587 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d00 as i32 as u16,
            high: 0x1d2b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d62 as i32 as u16,
            high: 0x1d6b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e01 as i32 as u16,
            high: 0x1e01 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e03 as i32 as u16,
            high: 0x1e03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e05 as i32 as u16,
            high: 0x1e05 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e07 as i32 as u16,
            high: 0x1e07 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e09 as i32 as u16,
            high: 0x1e09 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0b as i32 as u16,
            high: 0x1e0b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0d as i32 as u16,
            high: 0x1e0d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0f as i32 as u16,
            high: 0x1e0f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e11 as i32 as u16,
            high: 0x1e11 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e13 as i32 as u16,
            high: 0x1e13 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e15 as i32 as u16,
            high: 0x1e15 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e17 as i32 as u16,
            high: 0x1e17 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e19 as i32 as u16,
            high: 0x1e19 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1b as i32 as u16,
            high: 0x1e1b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1d as i32 as u16,
            high: 0x1e1d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1f as i32 as u16,
            high: 0x1e1f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e21 as i32 as u16,
            high: 0x1e21 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e23 as i32 as u16,
            high: 0x1e23 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e25 as i32 as u16,
            high: 0x1e25 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e27 as i32 as u16,
            high: 0x1e27 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e29 as i32 as u16,
            high: 0x1e29 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2b as i32 as u16,
            high: 0x1e2b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2d as i32 as u16,
            high: 0x1e2d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2f as i32 as u16,
            high: 0x1e2f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e31 as i32 as u16,
            high: 0x1e31 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e33 as i32 as u16,
            high: 0x1e33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e35 as i32 as u16,
            high: 0x1e35 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e37 as i32 as u16,
            high: 0x1e37 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e39 as i32 as u16,
            high: 0x1e39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3b as i32 as u16,
            high: 0x1e3b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3d as i32 as u16,
            high: 0x1e3d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3f as i32 as u16,
            high: 0x1e3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e41 as i32 as u16,
            high: 0x1e41 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e43 as i32 as u16,
            high: 0x1e43 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e45 as i32 as u16,
            high: 0x1e45 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e47 as i32 as u16,
            high: 0x1e47 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e49 as i32 as u16,
            high: 0x1e49 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4b as i32 as u16,
            high: 0x1e4b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4d as i32 as u16,
            high: 0x1e4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4f as i32 as u16,
            high: 0x1e4f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e51 as i32 as u16,
            high: 0x1e51 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e53 as i32 as u16,
            high: 0x1e53 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e55 as i32 as u16,
            high: 0x1e55 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e57 as i32 as u16,
            high: 0x1e57 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e59 as i32 as u16,
            high: 0x1e59 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5b as i32 as u16,
            high: 0x1e5b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5d as i32 as u16,
            high: 0x1e5d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5f as i32 as u16,
            high: 0x1e5f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e61 as i32 as u16,
            high: 0x1e61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e63 as i32 as u16,
            high: 0x1e63 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e65 as i32 as u16,
            high: 0x1e65 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e67 as i32 as u16,
            high: 0x1e67 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e69 as i32 as u16,
            high: 0x1e69 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6b as i32 as u16,
            high: 0x1e6b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6d as i32 as u16,
            high: 0x1e6d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6f as i32 as u16,
            high: 0x1e6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e71 as i32 as u16,
            high: 0x1e71 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e73 as i32 as u16,
            high: 0x1e73 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e75 as i32 as u16,
            high: 0x1e75 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e77 as i32 as u16,
            high: 0x1e77 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e79 as i32 as u16,
            high: 0x1e79 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7b as i32 as u16,
            high: 0x1e7b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7d as i32 as u16,
            high: 0x1e7d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7f as i32 as u16,
            high: 0x1e7f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e81 as i32 as u16,
            high: 0x1e81 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e83 as i32 as u16,
            high: 0x1e83 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e85 as i32 as u16,
            high: 0x1e85 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e87 as i32 as u16,
            high: 0x1e87 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e89 as i32 as u16,
            high: 0x1e89 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8b as i32 as u16,
            high: 0x1e8b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8d as i32 as u16,
            high: 0x1e8d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8f as i32 as u16,
            high: 0x1e8f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e91 as i32 as u16,
            high: 0x1e91 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e93 as i32 as u16,
            high: 0x1e93 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e95 as i32 as u16,
            high: 0x1e9b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea1 as i32 as u16,
            high: 0x1ea1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea3 as i32 as u16,
            high: 0x1ea3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea5 as i32 as u16,
            high: 0x1ea5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea7 as i32 as u16,
            high: 0x1ea7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea9 as i32 as u16,
            high: 0x1ea9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eab as i32 as u16,
            high: 0x1eab as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ead as i32 as u16,
            high: 0x1ead as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eaf as i32 as u16,
            high: 0x1eaf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb1 as i32 as u16,
            high: 0x1eb1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb3 as i32 as u16,
            high: 0x1eb3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb5 as i32 as u16,
            high: 0x1eb5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb7 as i32 as u16,
            high: 0x1eb7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb9 as i32 as u16,
            high: 0x1eb9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ebb as i32 as u16,
            high: 0x1ebb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ebd as i32 as u16,
            high: 0x1ebd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ebf as i32 as u16,
            high: 0x1ebf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec1 as i32 as u16,
            high: 0x1ec1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec3 as i32 as u16,
            high: 0x1ec3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec5 as i32 as u16,
            high: 0x1ec5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec7 as i32 as u16,
            high: 0x1ec7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec9 as i32 as u16,
            high: 0x1ec9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ecb as i32 as u16,
            high: 0x1ecb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ecd as i32 as u16,
            high: 0x1ecd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ecf as i32 as u16,
            high: 0x1ecf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed1 as i32 as u16,
            high: 0x1ed1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed3 as i32 as u16,
            high: 0x1ed3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed5 as i32 as u16,
            high: 0x1ed5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed7 as i32 as u16,
            high: 0x1ed7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed9 as i32 as u16,
            high: 0x1ed9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1edb as i32 as u16,
            high: 0x1edb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1edd as i32 as u16,
            high: 0x1edd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1edf as i32 as u16,
            high: 0x1edf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee1 as i32 as u16,
            high: 0x1ee1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee3 as i32 as u16,
            high: 0x1ee3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee5 as i32 as u16,
            high: 0x1ee5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee7 as i32 as u16,
            high: 0x1ee7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee9 as i32 as u16,
            high: 0x1ee9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eeb as i32 as u16,
            high: 0x1eeb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eed as i32 as u16,
            high: 0x1eed as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eef as i32 as u16,
            high: 0x1eef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef1 as i32 as u16,
            high: 0x1ef1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef3 as i32 as u16,
            high: 0x1ef3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef5 as i32 as u16,
            high: 0x1ef5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef7 as i32 as u16,
            high: 0x1ef7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef9 as i32 as u16,
            high: 0x1ef9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f00 as i32 as u16,
            high: 0x1f07 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f10 as i32 as u16,
            high: 0x1f15 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f20 as i32 as u16,
            high: 0x1f27 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f30 as i32 as u16,
            high: 0x1f37 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f40 as i32 as u16,
            high: 0x1f45 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f50 as i32 as u16,
            high: 0x1f57 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f60 as i32 as u16,
            high: 0x1f67 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f70 as i32 as u16,
            high: 0x1f7d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f80 as i32 as u16,
            high: 0x1f87 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f90 as i32 as u16,
            high: 0x1f97 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fa0 as i32 as u16,
            high: 0x1fa7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fb0 as i32 as u16,
            high: 0x1fb4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fb6 as i32 as u16,
            high: 0x1fb7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbe as i32 as u16,
            high: 0x1fbe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc2 as i32 as u16,
            high: 0x1fc4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc6 as i32 as u16,
            high: 0x1fc7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd0 as i32 as u16,
            high: 0x1fd3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd6 as i32 as u16,
            high: 0x1fd7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fe0 as i32 as u16,
            high: 0x1fe7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff2 as i32 as u16,
            high: 0x1ff4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff6 as i32 as u16,
            high: 0x1ff7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2071 as i32 as u16,
            high: 0x2071 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207f as i32 as u16,
            high: 0x207f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x210a as i32 as u16,
            high: 0x210a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x210e as i32 as u16,
            high: 0x210f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2113 as i32 as u16,
            high: 0x2113 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212f as i32 as u16,
            high: 0x212f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2134 as i32 as u16,
            high: 0x2134 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2139 as i32 as u16,
            high: 0x2139 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213d as i32 as u16,
            high: 0x213d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2146 as i32 as u16,
            high: 0x2149 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb00 as i32 as u16,
            high: 0xfb06 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb13 as i32 as u16,
            high: 0xfb17 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff41 as i32 as u16,
            high: 0xff5a as i32 as u16,
        };
        init
    },
];
static mut xmlLlL: [xmlChLRange; 28] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10428 as i32 as u32,
            high: 0x1044f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d41a as i32 as u32,
            high: 0x1d433 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d44e as i32 as u32,
            high: 0x1d454 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d456 as i32 as u32,
            high: 0x1d467 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d482 as i32 as u32,
            high: 0x1d49b as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4b6 as i32 as u32,
            high: 0x1d4b9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4bb as i32 as u32,
            high: 0x1d4bb as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4bd as i32 as u32,
            high: 0x1d4c3 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4c5 as i32 as u32,
            high: 0x1d4cf as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4ea as i32 as u32,
            high: 0x1d503 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d51e as i32 as u32,
            high: 0x1d537 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d552 as i32 as u32,
            high: 0x1d56b as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d586 as i32 as u32,
            high: 0x1d59f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d5ba as i32 as u32,
            high: 0x1d5d3 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d5ee as i32 as u32,
            high: 0x1d607 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d622 as i32 as u32,
            high: 0x1d63b as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d656 as i32 as u32,
            high: 0x1d66f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d68a as i32 as u32,
            high: 0x1d6a3 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6c2 as i32 as u32,
            high: 0x1d6da as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6dc as i32 as u32,
            high: 0x1d6e1 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6fc as i32 as u32,
            high: 0x1d714 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d716 as i32 as u32,
            high: 0x1d71b as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d736 as i32 as u32,
            high: 0x1d74e as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d750 as i32 as u32,
            high: 0x1d755 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d770 as i32 as u32,
            high: 0x1d788 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d78a as i32 as u32,
            high: 0x1d78f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7aa as i32 as u32,
            high: 0x1d7c2 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7c4 as i32 as u32,
            high: 0x1d7c9 as i32 as u32,
        };
        init
    },
];
static mut xmlLlG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 396 as i32,
            nbLongRange: 28 as i32,
            shortRange: xmlLlS.as_ptr(),
            longRange: xmlLlL.as_ptr(),
        };
        init
    }
};
static mut xmlLmS: [xmlChSRange; 20] = [
    {
        let mut init = _xmlChSRange {
            low: 0x2b0 as i32 as u16,
            high: 0x2c1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c6 as i32 as u16,
            high: 0x2d1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e0 as i32 as u16,
            high: 0x2e4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ee as i32 as u16,
            high: 0x2ee as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x37a as i32 as u16,
            high: 0x37a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x559 as i32 as u16,
            high: 0x559 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x640 as i32 as u16,
            high: 0x640 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e5 as i32 as u16,
            high: 0x6e6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe46 as i32 as u16,
            high: 0xe46 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec6 as i32 as u16,
            high: 0xec6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d7 as i32 as u16,
            high: 0x17d7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1843 as i32 as u16,
            high: 0x1843 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d2c as i32 as u16,
            high: 0x1d61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3005 as i32 as u16,
            high: 0x3005 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3031 as i32 as u16,
            high: 0x3035 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303b as i32 as u16,
            high: 0x303b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309d as i32 as u16,
            high: 0x309e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30fc as i32 as u16,
            high: 0x30fe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff70 as i32 as u16,
            high: 0xff70 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff9e as i32 as u16,
            high: 0xff9f as i32 as u16,
        };
        init
    },
];
static mut xmlLmG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 20 as i32,
            nbLongRange: 0 as i32,
            shortRange: xmlLmS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlLoS: [xmlChSRange; 211] = [
    {
        let mut init = _xmlChSRange {
            low: 0x1bb as i32 as u16,
            high: 0x1bb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c0 as i32 as u16,
            high: 0x1c3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5d0 as i32 as u16,
            high: 0x5ea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5f0 as i32 as u16,
            high: 0x5f2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x621 as i32 as u16,
            high: 0x63a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x641 as i32 as u16,
            high: 0x64a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x66e as i32 as u16,
            high: 0x66f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x671 as i32 as u16,
            high: 0x6d3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d5 as i32 as u16,
            high: 0x6d5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ee as i32 as u16,
            high: 0x6ef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6fa as i32 as u16,
            high: 0x6fc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ff as i32 as u16,
            high: 0x6ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x710 as i32 as u16,
            high: 0x710 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x712 as i32 as u16,
            high: 0x72f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x74d as i32 as u16,
            high: 0x74f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x780 as i32 as u16,
            high: 0x7a5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7b1 as i32 as u16,
            high: 0x7b1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x904 as i32 as u16,
            high: 0x939 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93d as i32 as u16,
            high: 0x93d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x950 as i32 as u16,
            high: 0x950 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x958 as i32 as u16,
            high: 0x961 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x985 as i32 as u16,
            high: 0x98c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x98f as i32 as u16,
            high: 0x990 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x993 as i32 as u16,
            high: 0x9a8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9aa as i32 as u16,
            high: 0x9b0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9b2 as i32 as u16,
            high: 0x9b2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9b6 as i32 as u16,
            high: 0x9b9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9bd as i32 as u16,
            high: 0x9bd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9dc as i32 as u16,
            high: 0x9dd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9df as i32 as u16,
            high: 0x9e1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f0 as i32 as u16,
            high: 0x9f1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa05 as i32 as u16,
            high: 0xa0a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa0f as i32 as u16,
            high: 0xa10 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa13 as i32 as u16,
            high: 0xa28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa2a as i32 as u16,
            high: 0xa30 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa32 as i32 as u16,
            high: 0xa33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa35 as i32 as u16,
            high: 0xa36 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa38 as i32 as u16,
            high: 0xa39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa59 as i32 as u16,
            high: 0xa5c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa5e as i32 as u16,
            high: 0xa5e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa72 as i32 as u16,
            high: 0xa74 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa85 as i32 as u16,
            high: 0xa8d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa8f as i32 as u16,
            high: 0xa91 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa93 as i32 as u16,
            high: 0xaa8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaaa as i32 as u16,
            high: 0xab0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xab2 as i32 as u16,
            high: 0xab3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xab5 as i32 as u16,
            high: 0xab9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabd as i32 as u16,
            high: 0xabd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xad0 as i32 as u16,
            high: 0xad0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae0 as i32 as u16,
            high: 0xae1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb05 as i32 as u16,
            high: 0xb0c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb0f as i32 as u16,
            high: 0xb10 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb13 as i32 as u16,
            high: 0xb28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb2a as i32 as u16,
            high: 0xb30 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb32 as i32 as u16,
            high: 0xb33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb35 as i32 as u16,
            high: 0xb39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3d as i32 as u16,
            high: 0xb3d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5c as i32 as u16,
            high: 0xb5d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5f as i32 as u16,
            high: 0xb61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb71 as i32 as u16,
            high: 0xb71 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb83 as i32 as u16,
            high: 0xb83 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb85 as i32 as u16,
            high: 0xb8a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb8e as i32 as u16,
            high: 0xb90 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb92 as i32 as u16,
            high: 0xb95 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb99 as i32 as u16,
            high: 0xb9a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9c as i32 as u16,
            high: 0xb9c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9e as i32 as u16,
            high: 0xb9f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba3 as i32 as u16,
            high: 0xba4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba8 as i32 as u16,
            high: 0xbaa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbae as i32 as u16,
            high: 0xbb5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbb7 as i32 as u16,
            high: 0xbb9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc05 as i32 as u16,
            high: 0xc0c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc0e as i32 as u16,
            high: 0xc10 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc12 as i32 as u16,
            high: 0xc28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc2a as i32 as u16,
            high: 0xc33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc35 as i32 as u16,
            high: 0xc39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc60 as i32 as u16,
            high: 0xc61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc85 as i32 as u16,
            high: 0xc8c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc8e as i32 as u16,
            high: 0xc90 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc92 as i32 as u16,
            high: 0xca8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcaa as i32 as u16,
            high: 0xcb3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcb5 as i32 as u16,
            high: 0xcb9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbd as i32 as u16,
            high: 0xcbd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcde as i32 as u16,
            high: 0xcde as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xce0 as i32 as u16,
            high: 0xce1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd05 as i32 as u16,
            high: 0xd0c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd0e as i32 as u16,
            high: 0xd10 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd12 as i32 as u16,
            high: 0xd28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd2a as i32 as u16,
            high: 0xd39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd60 as i32 as u16,
            high: 0xd61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd85 as i32 as u16,
            high: 0xd96 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd9a as i32 as u16,
            high: 0xdb1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdb3 as i32 as u16,
            high: 0xdbb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdbd as i32 as u16,
            high: 0xdbd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdc0 as i32 as u16,
            high: 0xdc6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe01 as i32 as u16,
            high: 0xe30 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe32 as i32 as u16,
            high: 0xe33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe40 as i32 as u16,
            high: 0xe45 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe81 as i32 as u16,
            high: 0xe82 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe84 as i32 as u16,
            high: 0xe84 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe87 as i32 as u16,
            high: 0xe88 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe8a as i32 as u16,
            high: 0xe8a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe8d as i32 as u16,
            high: 0xe8d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe94 as i32 as u16,
            high: 0xe97 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe99 as i32 as u16,
            high: 0xe9f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea1 as i32 as u16,
            high: 0xea3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea5 as i32 as u16,
            high: 0xea5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea7 as i32 as u16,
            high: 0xea7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeaa as i32 as u16,
            high: 0xeab as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xead as i32 as u16,
            high: 0xeb0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb2 as i32 as u16,
            high: 0xeb3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xebd as i32 as u16,
            high: 0xebd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec0 as i32 as u16,
            high: 0xec4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xedc as i32 as u16,
            high: 0xedd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf00 as i32 as u16,
            high: 0xf00 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf40 as i32 as u16,
            high: 0xf47 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf49 as i32 as u16,
            high: 0xf6a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf88 as i32 as u16,
            high: 0xf8b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1000 as i32 as u16,
            high: 0x1021 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1023 as i32 as u16,
            high: 0x1027 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1029 as i32 as u16,
            high: 0x102a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1050 as i32 as u16,
            high: 0x1055 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10d0 as i32 as u16,
            high: 0x10f8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1100 as i32 as u16,
            high: 0x1159 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x115f as i32 as u16,
            high: 0x11a2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11a8 as i32 as u16,
            high: 0x11f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1200 as i32 as u16,
            high: 0x1206 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1208 as i32 as u16,
            high: 0x1246 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1248 as i32 as u16,
            high: 0x1248 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x124a as i32 as u16,
            high: 0x124d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1250 as i32 as u16,
            high: 0x1256 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1258 as i32 as u16,
            high: 0x1258 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x125a as i32 as u16,
            high: 0x125d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1260 as i32 as u16,
            high: 0x1286 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1288 as i32 as u16,
            high: 0x1288 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x128a as i32 as u16,
            high: 0x128d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1290 as i32 as u16,
            high: 0x12ae as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b0 as i32 as u16,
            high: 0x12b0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b2 as i32 as u16,
            high: 0x12b5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b8 as i32 as u16,
            high: 0x12be as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c0 as i32 as u16,
            high: 0x12c0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c2 as i32 as u16,
            high: 0x12c5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c8 as i32 as u16,
            high: 0x12ce as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12d0 as i32 as u16,
            high: 0x12d6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12d8 as i32 as u16,
            high: 0x12ee as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12f0 as i32 as u16,
            high: 0x130e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1310 as i32 as u16,
            high: 0x1310 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1312 as i32 as u16,
            high: 0x1315 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1318 as i32 as u16,
            high: 0x131e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1320 as i32 as u16,
            high: 0x1346 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1348 as i32 as u16,
            high: 0x135a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13a0 as i32 as u16,
            high: 0x13f4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1401 as i32 as u16,
            high: 0x166c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x166f as i32 as u16,
            high: 0x1676 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1681 as i32 as u16,
            high: 0x169a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16a0 as i32 as u16,
            high: 0x16ea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1700 as i32 as u16,
            high: 0x170c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x170e as i32 as u16,
            high: 0x1711 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1720 as i32 as u16,
            high: 0x1731 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1740 as i32 as u16,
            high: 0x1751 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1760 as i32 as u16,
            high: 0x176c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x176e as i32 as u16,
            high: 0x1770 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1780 as i32 as u16,
            high: 0x17b3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17dc as i32 as u16,
            high: 0x17dc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1820 as i32 as u16,
            high: 0x1842 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1844 as i32 as u16,
            high: 0x1877 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1880 as i32 as u16,
            high: 0x18a8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1900 as i32 as u16,
            high: 0x191c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1950 as i32 as u16,
            high: 0x196d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1970 as i32 as u16,
            high: 0x1974 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2135 as i32 as u16,
            high: 0x2138 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3006 as i32 as u16,
            high: 0x3006 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303c as i32 as u16,
            high: 0x303c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3041 as i32 as u16,
            high: 0x3096 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309f as i32 as u16,
            high: 0x309f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30a1 as i32 as u16,
            high: 0x30fa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30ff as i32 as u16,
            high: 0x30ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3105 as i32 as u16,
            high: 0x312c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3131 as i32 as u16,
            high: 0x318e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x31a0 as i32 as u16,
            high: 0x31b7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x31f0 as i32 as u16,
            high: 0x31ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3400 as i32 as u16,
            high: 0x3400 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4db5 as i32 as u16,
            high: 0x4db5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e00 as i32 as u16,
            high: 0x4e00 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9fa5 as i32 as u16,
            high: 0x9fa5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa000 as i32 as u16,
            high: 0xa48c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac00 as i32 as u16,
            high: 0xac00 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd7a3 as i32 as u16,
            high: 0xd7a3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf900 as i32 as u16,
            high: 0xfa2d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfa30 as i32 as u16,
            high: 0xfa6a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1d as i32 as u16,
            high: 0xfb1d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1f as i32 as u16,
            high: 0xfb28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb2a as i32 as u16,
            high: 0xfb36 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb38 as i32 as u16,
            high: 0xfb3c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb3e as i32 as u16,
            high: 0xfb3e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb40 as i32 as u16,
            high: 0xfb41 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb43 as i32 as u16,
            high: 0xfb44 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb46 as i32 as u16,
            high: 0xfbb1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfbd3 as i32 as u16,
            high: 0xfd3d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd50 as i32 as u16,
            high: 0xfd8f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd92 as i32 as u16,
            high: 0xfdc7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfdf0 as i32 as u16,
            high: 0xfdfb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe70 as i32 as u16,
            high: 0xfe74 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe76 as i32 as u16,
            high: 0xfefc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff66 as i32 as u16,
            high: 0xff6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff71 as i32 as u16,
            high: 0xff9d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffa0 as i32 as u16,
            high: 0xffbe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffc2 as i32 as u16,
            high: 0xffc7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffca as i32 as u16,
            high: 0xffcf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffd2 as i32 as u16,
            high: 0xffd7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffda as i32 as u16,
            high: 0xffdc as i32 as u16,
        };
        init
    },
];
static mut xmlLoL: [xmlChLRange; 20] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10000 as i32 as u32,
            high: 0x1000b as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1000d as i32 as u32,
            high: 0x10026 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10028 as i32 as u32,
            high: 0x1003a as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1003c as i32 as u32,
            high: 0x1003d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1003f as i32 as u32,
            high: 0x1004d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10050 as i32 as u32,
            high: 0x1005d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10080 as i32 as u32,
            high: 0x100fa as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10300 as i32 as u32,
            high: 0x1031e as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10330 as i32 as u32,
            high: 0x10349 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10380 as i32 as u32,
            high: 0x1039d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10450 as i32 as u32,
            high: 0x1049d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10800 as i32 as u32,
            high: 0x10805 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10808 as i32 as u32,
            high: 0x10808 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1080a as i32 as u32,
            high: 0x10835 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10837 as i32 as u32,
            high: 0x10838 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1083c as i32 as u32,
            high: 0x1083c as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1083f as i32 as u32,
            high: 0x1083f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x20000 as i32 as u32,
            high: 0x20000 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x2a6d6 as i32 as u32,
            high: 0x2a6d6 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x2f800 as i32 as u32,
            high: 0x2fa1d as i32 as u32,
        };
        init
    },
];
static mut xmlLoG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 211 as i32,
            nbLongRange: 20 as i32,
            shortRange: xmlLoS.as_ptr(),
            longRange: xmlLoL.as_ptr(),
        };
        init
    }
};
static mut xmlLtS: [xmlChSRange; 10] = [
    {
        let mut init = _xmlChSRange {
            low: 0x1c5 as i32 as u16,
            high: 0x1c5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c8 as i32 as u16,
            high: 0x1c8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1cb as i32 as u16,
            high: 0x1cb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f2 as i32 as u16,
            high: 0x1f2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f88 as i32 as u16,
            high: 0x1f8f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f98 as i32 as u16,
            high: 0x1f9f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fa8 as i32 as u16,
            high: 0x1faf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbc as i32 as u16,
            high: 0x1fbc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fcc as i32 as u16,
            high: 0x1fcc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ffc as i32 as u16,
            high: 0x1ffc as i32 as u16,
        };
        init
    },
];
static mut xmlLtG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 10 as i32,
            nbLongRange: 0 as i32,
            shortRange: xmlLtS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlLuS: [xmlChSRange; 390] = [
    {
        let mut init = _xmlChSRange {
            low: 0x41 as i32 as u16,
            high: 0x5a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc0 as i32 as u16,
            high: 0xd6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd8 as i32 as u16,
            high: 0xde as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x100 as i32 as u16,
            high: 0x100 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x102 as i32 as u16,
            high: 0x102 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x104 as i32 as u16,
            high: 0x104 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x106 as i32 as u16,
            high: 0x106 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x108 as i32 as u16,
            high: 0x108 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10a as i32 as u16,
            high: 0x10a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10c as i32 as u16,
            high: 0x10c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10e as i32 as u16,
            high: 0x10e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x110 as i32 as u16,
            high: 0x110 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x112 as i32 as u16,
            high: 0x112 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x114 as i32 as u16,
            high: 0x114 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x116 as i32 as u16,
            high: 0x116 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x118 as i32 as u16,
            high: 0x118 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11a as i32 as u16,
            high: 0x11a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11c as i32 as u16,
            high: 0x11c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11e as i32 as u16,
            high: 0x11e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x120 as i32 as u16,
            high: 0x120 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x122 as i32 as u16,
            high: 0x122 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x124 as i32 as u16,
            high: 0x124 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x126 as i32 as u16,
            high: 0x126 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x128 as i32 as u16,
            high: 0x128 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12a as i32 as u16,
            high: 0x12a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c as i32 as u16,
            high: 0x12c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12e as i32 as u16,
            high: 0x12e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x130 as i32 as u16,
            high: 0x130 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x132 as i32 as u16,
            high: 0x132 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x134 as i32 as u16,
            high: 0x134 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x136 as i32 as u16,
            high: 0x136 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x139 as i32 as u16,
            high: 0x139 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13b as i32 as u16,
            high: 0x13b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13d as i32 as u16,
            high: 0x13d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13f as i32 as u16,
            high: 0x13f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x141 as i32 as u16,
            high: 0x141 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x143 as i32 as u16,
            high: 0x143 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x145 as i32 as u16,
            high: 0x145 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x147 as i32 as u16,
            high: 0x147 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14a as i32 as u16,
            high: 0x14a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14c as i32 as u16,
            high: 0x14c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14e as i32 as u16,
            high: 0x14e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x150 as i32 as u16,
            high: 0x150 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x152 as i32 as u16,
            high: 0x152 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x154 as i32 as u16,
            high: 0x154 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x156 as i32 as u16,
            high: 0x156 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x158 as i32 as u16,
            high: 0x158 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15a as i32 as u16,
            high: 0x15a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15c as i32 as u16,
            high: 0x15c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15e as i32 as u16,
            high: 0x15e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x160 as i32 as u16,
            high: 0x160 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x162 as i32 as u16,
            high: 0x162 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x164 as i32 as u16,
            high: 0x164 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x166 as i32 as u16,
            high: 0x166 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x168 as i32 as u16,
            high: 0x168 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16a as i32 as u16,
            high: 0x16a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16c as i32 as u16,
            high: 0x16c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16e as i32 as u16,
            high: 0x16e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x170 as i32 as u16,
            high: 0x170 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x172 as i32 as u16,
            high: 0x172 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x174 as i32 as u16,
            high: 0x174 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x176 as i32 as u16,
            high: 0x176 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x178 as i32 as u16,
            high: 0x179 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b as i32 as u16,
            high: 0x17b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d as i32 as u16,
            high: 0x17d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x181 as i32 as u16,
            high: 0x182 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x184 as i32 as u16,
            high: 0x184 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x186 as i32 as u16,
            high: 0x187 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x189 as i32 as u16,
            high: 0x18b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x18e as i32 as u16,
            high: 0x191 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x193 as i32 as u16,
            high: 0x194 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x196 as i32 as u16,
            high: 0x198 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x19c as i32 as u16,
            high: 0x19d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x19f as i32 as u16,
            high: 0x1a0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a2 as i32 as u16,
            high: 0x1a2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a4 as i32 as u16,
            high: 0x1a4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a6 as i32 as u16,
            high: 0x1a7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a9 as i32 as u16,
            high: 0x1a9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ac as i32 as u16,
            high: 0x1ac as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ae as i32 as u16,
            high: 0x1af as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b1 as i32 as u16,
            high: 0x1b3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b5 as i32 as u16,
            high: 0x1b5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b7 as i32 as u16,
            high: 0x1b8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1bc as i32 as u16,
            high: 0x1bc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c4 as i32 as u16,
            high: 0x1c4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c7 as i32 as u16,
            high: 0x1c7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ca as i32 as u16,
            high: 0x1ca as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1cd as i32 as u16,
            high: 0x1cd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1cf as i32 as u16,
            high: 0x1cf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d1 as i32 as u16,
            high: 0x1d1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d3 as i32 as u16,
            high: 0x1d3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d5 as i32 as u16,
            high: 0x1d5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d7 as i32 as u16,
            high: 0x1d7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d9 as i32 as u16,
            high: 0x1d9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1db as i32 as u16,
            high: 0x1db as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1de as i32 as u16,
            high: 0x1de as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0 as i32 as u16,
            high: 0x1e0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2 as i32 as u16,
            high: 0x1e2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4 as i32 as u16,
            high: 0x1e4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6 as i32 as u16,
            high: 0x1e6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8 as i32 as u16,
            high: 0x1e8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea as i32 as u16,
            high: 0x1ea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec as i32 as u16,
            high: 0x1ec as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee as i32 as u16,
            high: 0x1ee as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f1 as i32 as u16,
            high: 0x1f1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f4 as i32 as u16,
            high: 0x1f4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f6 as i32 as u16,
            high: 0x1f8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fa as i32 as u16,
            high: 0x1fa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc as i32 as u16,
            high: 0x1fc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fe as i32 as u16,
            high: 0x1fe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x200 as i32 as u16,
            high: 0x200 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x202 as i32 as u16,
            high: 0x202 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x204 as i32 as u16,
            high: 0x204 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x206 as i32 as u16,
            high: 0x206 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208 as i32 as u16,
            high: 0x208 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20a as i32 as u16,
            high: 0x20a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20c as i32 as u16,
            high: 0x20c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20e as i32 as u16,
            high: 0x20e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x210 as i32 as u16,
            high: 0x210 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212 as i32 as u16,
            high: 0x212 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x214 as i32 as u16,
            high: 0x214 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x216 as i32 as u16,
            high: 0x216 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x218 as i32 as u16,
            high: 0x218 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a as i32 as u16,
            high: 0x21a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21c as i32 as u16,
            high: 0x21c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21e as i32 as u16,
            high: 0x21e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x220 as i32 as u16,
            high: 0x220 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x222 as i32 as u16,
            high: 0x222 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x224 as i32 as u16,
            high: 0x224 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x226 as i32 as u16,
            high: 0x226 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x228 as i32 as u16,
            high: 0x228 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22a as i32 as u16,
            high: 0x22a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22c as i32 as u16,
            high: 0x22c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22e as i32 as u16,
            high: 0x22e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x230 as i32 as u16,
            high: 0x230 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x232 as i32 as u16,
            high: 0x232 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x386 as i32 as u16,
            high: 0x386 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x388 as i32 as u16,
            high: 0x38a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x38c as i32 as u16,
            high: 0x38c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x38e as i32 as u16,
            high: 0x38f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x391 as i32 as u16,
            high: 0x3a1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3a3 as i32 as u16,
            high: 0x3ab as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d2 as i32 as u16,
            high: 0x3d4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d8 as i32 as u16,
            high: 0x3d8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3da as i32 as u16,
            high: 0x3da as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3dc as i32 as u16,
            high: 0x3dc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3de as i32 as u16,
            high: 0x3de as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e0 as i32 as u16,
            high: 0x3e0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e2 as i32 as u16,
            high: 0x3e2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e4 as i32 as u16,
            high: 0x3e4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e6 as i32 as u16,
            high: 0x3e6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e8 as i32 as u16,
            high: 0x3e8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ea as i32 as u16,
            high: 0x3ea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ec as i32 as u16,
            high: 0x3ec as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ee as i32 as u16,
            high: 0x3ee as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f4 as i32 as u16,
            high: 0x3f4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f7 as i32 as u16,
            high: 0x3f7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f9 as i32 as u16,
            high: 0x3fa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x400 as i32 as u16,
            high: 0x42f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x460 as i32 as u16,
            high: 0x460 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x462 as i32 as u16,
            high: 0x462 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x464 as i32 as u16,
            high: 0x464 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x466 as i32 as u16,
            high: 0x466 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x468 as i32 as u16,
            high: 0x468 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46a as i32 as u16,
            high: 0x46a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46c as i32 as u16,
            high: 0x46c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46e as i32 as u16,
            high: 0x46e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x470 as i32 as u16,
            high: 0x470 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x472 as i32 as u16,
            high: 0x472 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x474 as i32 as u16,
            high: 0x474 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x476 as i32 as u16,
            high: 0x476 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x478 as i32 as u16,
            high: 0x478 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47a as i32 as u16,
            high: 0x47a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47c as i32 as u16,
            high: 0x47c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47e as i32 as u16,
            high: 0x47e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x480 as i32 as u16,
            high: 0x480 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48a as i32 as u16,
            high: 0x48a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48c as i32 as u16,
            high: 0x48c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48e as i32 as u16,
            high: 0x48e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x490 as i32 as u16,
            high: 0x490 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x492 as i32 as u16,
            high: 0x492 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x494 as i32 as u16,
            high: 0x494 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x496 as i32 as u16,
            high: 0x496 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x498 as i32 as u16,
            high: 0x498 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49a as i32 as u16,
            high: 0x49a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49c as i32 as u16,
            high: 0x49c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49e as i32 as u16,
            high: 0x49e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a0 as i32 as u16,
            high: 0x4a0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a2 as i32 as u16,
            high: 0x4a2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a4 as i32 as u16,
            high: 0x4a4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a6 as i32 as u16,
            high: 0x4a6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a8 as i32 as u16,
            high: 0x4a8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4aa as i32 as u16,
            high: 0x4aa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ac as i32 as u16,
            high: 0x4ac as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ae as i32 as u16,
            high: 0x4ae as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b0 as i32 as u16,
            high: 0x4b0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b2 as i32 as u16,
            high: 0x4b2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b4 as i32 as u16,
            high: 0x4b4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b6 as i32 as u16,
            high: 0x4b6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b8 as i32 as u16,
            high: 0x4b8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ba as i32 as u16,
            high: 0x4ba as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4bc as i32 as u16,
            high: 0x4bc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4be as i32 as u16,
            high: 0x4be as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c0 as i32 as u16,
            high: 0x4c1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c3 as i32 as u16,
            high: 0x4c3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c5 as i32 as u16,
            high: 0x4c5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c7 as i32 as u16,
            high: 0x4c7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c9 as i32 as u16,
            high: 0x4c9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4cb as i32 as u16,
            high: 0x4cb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4cd as i32 as u16,
            high: 0x4cd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d0 as i32 as u16,
            high: 0x4d0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d2 as i32 as u16,
            high: 0x4d2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d4 as i32 as u16,
            high: 0x4d4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d6 as i32 as u16,
            high: 0x4d6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d8 as i32 as u16,
            high: 0x4d8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4da as i32 as u16,
            high: 0x4da as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4dc as i32 as u16,
            high: 0x4dc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4de as i32 as u16,
            high: 0x4de as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e0 as i32 as u16,
            high: 0x4e0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e2 as i32 as u16,
            high: 0x4e2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e4 as i32 as u16,
            high: 0x4e4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e6 as i32 as u16,
            high: 0x4e6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e8 as i32 as u16,
            high: 0x4e8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ea as i32 as u16,
            high: 0x4ea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ec as i32 as u16,
            high: 0x4ec as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ee as i32 as u16,
            high: 0x4ee as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f0 as i32 as u16,
            high: 0x4f0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f2 as i32 as u16,
            high: 0x4f2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f4 as i32 as u16,
            high: 0x4f4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f8 as i32 as u16,
            high: 0x4f8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x500 as i32 as u16,
            high: 0x500 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x502 as i32 as u16,
            high: 0x502 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x504 as i32 as u16,
            high: 0x504 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x506 as i32 as u16,
            high: 0x506 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x508 as i32 as u16,
            high: 0x508 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50a as i32 as u16,
            high: 0x50a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50c as i32 as u16,
            high: 0x50c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50e as i32 as u16,
            high: 0x50e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x531 as i32 as u16,
            high: 0x556 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10a0 as i32 as u16,
            high: 0x10c5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e00 as i32 as u16,
            high: 0x1e00 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e02 as i32 as u16,
            high: 0x1e02 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e04 as i32 as u16,
            high: 0x1e04 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e06 as i32 as u16,
            high: 0x1e06 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e08 as i32 as u16,
            high: 0x1e08 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0a as i32 as u16,
            high: 0x1e0a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0c as i32 as u16,
            high: 0x1e0c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0e as i32 as u16,
            high: 0x1e0e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e10 as i32 as u16,
            high: 0x1e10 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e12 as i32 as u16,
            high: 0x1e12 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e14 as i32 as u16,
            high: 0x1e14 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e16 as i32 as u16,
            high: 0x1e16 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e18 as i32 as u16,
            high: 0x1e18 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1a as i32 as u16,
            high: 0x1e1a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1c as i32 as u16,
            high: 0x1e1c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1e as i32 as u16,
            high: 0x1e1e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e20 as i32 as u16,
            high: 0x1e20 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e22 as i32 as u16,
            high: 0x1e22 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e24 as i32 as u16,
            high: 0x1e24 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e26 as i32 as u16,
            high: 0x1e26 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e28 as i32 as u16,
            high: 0x1e28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2a as i32 as u16,
            high: 0x1e2a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2c as i32 as u16,
            high: 0x1e2c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2e as i32 as u16,
            high: 0x1e2e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e30 as i32 as u16,
            high: 0x1e30 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e32 as i32 as u16,
            high: 0x1e32 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e34 as i32 as u16,
            high: 0x1e34 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e36 as i32 as u16,
            high: 0x1e36 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e38 as i32 as u16,
            high: 0x1e38 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3a as i32 as u16,
            high: 0x1e3a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3c as i32 as u16,
            high: 0x1e3c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3e as i32 as u16,
            high: 0x1e3e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e40 as i32 as u16,
            high: 0x1e40 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e42 as i32 as u16,
            high: 0x1e42 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e44 as i32 as u16,
            high: 0x1e44 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e46 as i32 as u16,
            high: 0x1e46 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e48 as i32 as u16,
            high: 0x1e48 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4a as i32 as u16,
            high: 0x1e4a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4c as i32 as u16,
            high: 0x1e4c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4e as i32 as u16,
            high: 0x1e4e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e50 as i32 as u16,
            high: 0x1e50 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e52 as i32 as u16,
            high: 0x1e52 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e54 as i32 as u16,
            high: 0x1e54 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e56 as i32 as u16,
            high: 0x1e56 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e58 as i32 as u16,
            high: 0x1e58 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5a as i32 as u16,
            high: 0x1e5a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5c as i32 as u16,
            high: 0x1e5c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5e as i32 as u16,
            high: 0x1e5e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e60 as i32 as u16,
            high: 0x1e60 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e62 as i32 as u16,
            high: 0x1e62 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e64 as i32 as u16,
            high: 0x1e64 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e66 as i32 as u16,
            high: 0x1e66 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e68 as i32 as u16,
            high: 0x1e68 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6a as i32 as u16,
            high: 0x1e6a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6c as i32 as u16,
            high: 0x1e6c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6e as i32 as u16,
            high: 0x1e6e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e70 as i32 as u16,
            high: 0x1e70 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e72 as i32 as u16,
            high: 0x1e72 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e74 as i32 as u16,
            high: 0x1e74 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e76 as i32 as u16,
            high: 0x1e76 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e78 as i32 as u16,
            high: 0x1e78 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7a as i32 as u16,
            high: 0x1e7a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7c as i32 as u16,
            high: 0x1e7c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7e as i32 as u16,
            high: 0x1e7e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e80 as i32 as u16,
            high: 0x1e80 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e82 as i32 as u16,
            high: 0x1e82 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e84 as i32 as u16,
            high: 0x1e84 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e86 as i32 as u16,
            high: 0x1e86 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e88 as i32 as u16,
            high: 0x1e88 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8a as i32 as u16,
            high: 0x1e8a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8c as i32 as u16,
            high: 0x1e8c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8e as i32 as u16,
            high: 0x1e8e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e90 as i32 as u16,
            high: 0x1e90 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e92 as i32 as u16,
            high: 0x1e92 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e94 as i32 as u16,
            high: 0x1e94 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea0 as i32 as u16,
            high: 0x1ea0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea2 as i32 as u16,
            high: 0x1ea2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea4 as i32 as u16,
            high: 0x1ea4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea6 as i32 as u16,
            high: 0x1ea6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea8 as i32 as u16,
            high: 0x1ea8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eaa as i32 as u16,
            high: 0x1eaa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eac as i32 as u16,
            high: 0x1eac as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eae as i32 as u16,
            high: 0x1eae as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb0 as i32 as u16,
            high: 0x1eb0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb2 as i32 as u16,
            high: 0x1eb2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb4 as i32 as u16,
            high: 0x1eb4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb6 as i32 as u16,
            high: 0x1eb6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb8 as i32 as u16,
            high: 0x1eb8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eba as i32 as u16,
            high: 0x1eba as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ebc as i32 as u16,
            high: 0x1ebc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ebe as i32 as u16,
            high: 0x1ebe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec0 as i32 as u16,
            high: 0x1ec0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec2 as i32 as u16,
            high: 0x1ec2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec4 as i32 as u16,
            high: 0x1ec4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec6 as i32 as u16,
            high: 0x1ec6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec8 as i32 as u16,
            high: 0x1ec8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eca as i32 as u16,
            high: 0x1eca as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ecc as i32 as u16,
            high: 0x1ecc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ece as i32 as u16,
            high: 0x1ece as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed0 as i32 as u16,
            high: 0x1ed0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed2 as i32 as u16,
            high: 0x1ed2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed4 as i32 as u16,
            high: 0x1ed4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed6 as i32 as u16,
            high: 0x1ed6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed8 as i32 as u16,
            high: 0x1ed8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eda as i32 as u16,
            high: 0x1eda as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1edc as i32 as u16,
            high: 0x1edc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ede as i32 as u16,
            high: 0x1ede as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee0 as i32 as u16,
            high: 0x1ee0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee2 as i32 as u16,
            high: 0x1ee2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee4 as i32 as u16,
            high: 0x1ee4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee6 as i32 as u16,
            high: 0x1ee6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee8 as i32 as u16,
            high: 0x1ee8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eea as i32 as u16,
            high: 0x1eea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eec as i32 as u16,
            high: 0x1eec as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eee as i32 as u16,
            high: 0x1eee as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef0 as i32 as u16,
            high: 0x1ef0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef2 as i32 as u16,
            high: 0x1ef2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef4 as i32 as u16,
            high: 0x1ef4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef6 as i32 as u16,
            high: 0x1ef6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef8 as i32 as u16,
            high: 0x1ef8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f08 as i32 as u16,
            high: 0x1f0f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f18 as i32 as u16,
            high: 0x1f1d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f28 as i32 as u16,
            high: 0x1f2f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f38 as i32 as u16,
            high: 0x1f3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f48 as i32 as u16,
            high: 0x1f4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f59 as i32 as u16,
            high: 0x1f59 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5b as i32 as u16,
            high: 0x1f5b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5d as i32 as u16,
            high: 0x1f5d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5f as i32 as u16,
            high: 0x1f5f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f68 as i32 as u16,
            high: 0x1f6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fb8 as i32 as u16,
            high: 0x1fbb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc8 as i32 as u16,
            high: 0x1fcb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd8 as i32 as u16,
            high: 0x1fdb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fe8 as i32 as u16,
            high: 0x1fec as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff8 as i32 as u16,
            high: 0x1ffb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2102 as i32 as u16,
            high: 0x2102 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2107 as i32 as u16,
            high: 0x2107 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x210b as i32 as u16,
            high: 0x210d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2110 as i32 as u16,
            high: 0x2112 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2115 as i32 as u16,
            high: 0x2115 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2119 as i32 as u16,
            high: 0x211d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2124 as i32 as u16,
            high: 0x2124 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2126 as i32 as u16,
            high: 0x2126 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2128 as i32 as u16,
            high: 0x2128 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212a as i32 as u16,
            high: 0x212d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2130 as i32 as u16,
            high: 0x2131 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2133 as i32 as u16,
            high: 0x2133 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213e as i32 as u16,
            high: 0x213f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2145 as i32 as u16,
            high: 0x2145 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff21 as i32 as u16,
            high: 0xff3a as i32 as u16,
        };
        init
    },
];
static mut xmlLuL: [xmlChLRange; 31] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10400 as i32 as u32,
            high: 0x10427 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d400 as i32 as u32,
            high: 0x1d419 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d434 as i32 as u32,
            high: 0x1d44d as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d468 as i32 as u32,
            high: 0x1d481 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d49c as i32 as u32,
            high: 0x1d49c as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d49e as i32 as u32,
            high: 0x1d49f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a2 as i32 as u32,
            high: 0x1d4a2 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a5 as i32 as u32,
            high: 0x1d4a6 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a9 as i32 as u32,
            high: 0x1d4ac as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4ae as i32 as u32,
            high: 0x1d4b5 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4d0 as i32 as u32,
            high: 0x1d4e9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d504 as i32 as u32,
            high: 0x1d505 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d507 as i32 as u32,
            high: 0x1d50a as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d50d as i32 as u32,
            high: 0x1d514 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d516 as i32 as u32,
            high: 0x1d51c as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d538 as i32 as u32,
            high: 0x1d539 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d53b as i32 as u32,
            high: 0x1d53e as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d540 as i32 as u32,
            high: 0x1d544 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d546 as i32 as u32,
            high: 0x1d546 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d54a as i32 as u32,
            high: 0x1d550 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d56c as i32 as u32,
            high: 0x1d585 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d5a0 as i32 as u32,
            high: 0x1d5b9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d5d4 as i32 as u32,
            high: 0x1d5ed as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d608 as i32 as u32,
            high: 0x1d621 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d63c as i32 as u32,
            high: 0x1d655 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d670 as i32 as u32,
            high: 0x1d689 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6a8 as i32 as u32,
            high: 0x1d6c0 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6e2 as i32 as u32,
            high: 0x1d6fa as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d71c as i32 as u32,
            high: 0x1d734 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d756 as i32 as u32,
            high: 0x1d76e as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d790 as i32 as u32,
            high: 0x1d7a8 as i32 as u32,
        };
        init
    },
];
static mut xmlLuG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 390 as i32,
            nbLongRange: 31 as i32,
            shortRange: xmlLuS.as_ptr(),
            longRange: xmlLuL.as_ptr(),
        };
        init
    }
};
static mut xmlMS: [xmlChSRange; 113] = [
    {
        let mut init = _xmlChSRange {
            low: 0x300 as i32 as u16,
            high: 0x357 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x35d as i32 as u16,
            high: 0x36f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x483 as i32 as u16,
            high: 0x486 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x488 as i32 as u16,
            high: 0x489 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x591 as i32 as u16,
            high: 0x5a1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5a3 as i32 as u16,
            high: 0x5b9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5bb as i32 as u16,
            high: 0x5bd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5bf as i32 as u16,
            high: 0x5bf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c1 as i32 as u16,
            high: 0x5c2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c4 as i32 as u16,
            high: 0x5c4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x610 as i32 as u16,
            high: 0x615 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x64b as i32 as u16,
            high: 0x658 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x670 as i32 as u16,
            high: 0x670 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d6 as i32 as u16,
            high: 0x6dc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6de as i32 as u16,
            high: 0x6e4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e7 as i32 as u16,
            high: 0x6e8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ea as i32 as u16,
            high: 0x6ed as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x711 as i32 as u16,
            high: 0x711 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x730 as i32 as u16,
            high: 0x74a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7a6 as i32 as u16,
            high: 0x7b0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x901 as i32 as u16,
            high: 0x903 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93c as i32 as u16,
            high: 0x93c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93e as i32 as u16,
            high: 0x94d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x951 as i32 as u16,
            high: 0x954 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x962 as i32 as u16,
            high: 0x963 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x981 as i32 as u16,
            high: 0x983 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9bc as i32 as u16,
            high: 0x9bc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9be as i32 as u16,
            high: 0x9c4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9c7 as i32 as u16,
            high: 0x9c8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9cb as i32 as u16,
            high: 0x9cd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9d7 as i32 as u16,
            high: 0x9d7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9e2 as i32 as u16,
            high: 0x9e3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa01 as i32 as u16,
            high: 0xa03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa3c as i32 as u16,
            high: 0xa3c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa3e as i32 as u16,
            high: 0xa42 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa47 as i32 as u16,
            high: 0xa48 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa4b as i32 as u16,
            high: 0xa4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa70 as i32 as u16,
            high: 0xa71 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa81 as i32 as u16,
            high: 0xa83 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabc as i32 as u16,
            high: 0xabc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabe as i32 as u16,
            high: 0xac5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac7 as i32 as u16,
            high: 0xac9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xacb as i32 as u16,
            high: 0xacd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae2 as i32 as u16,
            high: 0xae3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb01 as i32 as u16,
            high: 0xb03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3c as i32 as u16,
            high: 0xb3c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3e as i32 as u16,
            high: 0xb43 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb47 as i32 as u16,
            high: 0xb48 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb4b as i32 as u16,
            high: 0xb4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb56 as i32 as u16,
            high: 0xb57 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb82 as i32 as u16,
            high: 0xb82 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbbe as i32 as u16,
            high: 0xbc2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc6 as i32 as u16,
            high: 0xbc8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbca as i32 as u16,
            high: 0xbcd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbd7 as i32 as u16,
            high: 0xbd7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc01 as i32 as u16,
            high: 0xc03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc3e as i32 as u16,
            high: 0xc44 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc46 as i32 as u16,
            high: 0xc48 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc4a as i32 as u16,
            high: 0xc4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc55 as i32 as u16,
            high: 0xc56 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc82 as i32 as u16,
            high: 0xc83 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbc as i32 as u16,
            high: 0xcbc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbe as i32 as u16,
            high: 0xcc4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcc6 as i32 as u16,
            high: 0xcc8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcca as i32 as u16,
            high: 0xccd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcd5 as i32 as u16,
            high: 0xcd6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd02 as i32 as u16,
            high: 0xd03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd3e as i32 as u16,
            high: 0xd43 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd46 as i32 as u16,
            high: 0xd48 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd4a as i32 as u16,
            high: 0xd4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd57 as i32 as u16,
            high: 0xd57 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd82 as i32 as u16,
            high: 0xd83 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdca as i32 as u16,
            high: 0xdca as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdcf as i32 as u16,
            high: 0xdd4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdd6 as i32 as u16,
            high: 0xdd6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdd8 as i32 as u16,
            high: 0xddf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdf2 as i32 as u16,
            high: 0xdf3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe31 as i32 as u16,
            high: 0xe31 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe34 as i32 as u16,
            high: 0xe3a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe47 as i32 as u16,
            high: 0xe4e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb1 as i32 as u16,
            high: 0xeb1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb4 as i32 as u16,
            high: 0xeb9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xebb as i32 as u16,
            high: 0xebc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec8 as i32 as u16,
            high: 0xecd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf18 as i32 as u16,
            high: 0xf19 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf35 as i32 as u16,
            high: 0xf35 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf37 as i32 as u16,
            high: 0xf37 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf39 as i32 as u16,
            high: 0xf39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3e as i32 as u16,
            high: 0xf3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf71 as i32 as u16,
            high: 0xf84 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf86 as i32 as u16,
            high: 0xf87 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf90 as i32 as u16,
            high: 0xf97 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf99 as i32 as u16,
            high: 0xfbc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfc6 as i32 as u16,
            high: 0xfc6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x102c as i32 as u16,
            high: 0x1032 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1036 as i32 as u16,
            high: 0x1039 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1056 as i32 as u16,
            high: 0x1059 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1712 as i32 as u16,
            high: 0x1714 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1732 as i32 as u16,
            high: 0x1734 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1752 as i32 as u16,
            high: 0x1753 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1772 as i32 as u16,
            high: 0x1773 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b6 as i32 as u16,
            high: 0x17d3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17dd as i32 as u16,
            high: 0x17dd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x180b as i32 as u16,
            high: 0x180d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x18a9 as i32 as u16,
            high: 0x18a9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1920 as i32 as u16,
            high: 0x192b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1930 as i32 as u16,
            high: 0x193b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20d0 as i32 as u16,
            high: 0x20ea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x302a as i32 as u16,
            high: 0x302f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3099 as i32 as u16,
            high: 0x309a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1e as i32 as u16,
            high: 0xfb1e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe00 as i32 as u16,
            high: 0xfe0f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe20 as i32 as u16,
            high: 0xfe23 as i32 as u16,
        };
        init
    },
];
static mut xmlML: [xmlChLRange; 6] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d165 as i32 as u32,
            high: 0x1d169 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d16d as i32 as u32,
            high: 0x1d172 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d17b as i32 as u32,
            high: 0x1d182 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d185 as i32 as u32,
            high: 0x1d18b as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d1aa as i32 as u32,
            high: 0x1d1ad as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0100 as i32 as u32,
            high: 0xe01ef as i32 as u32,
        };
        init
    },
];
static mut xmlMG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 113 as i32,
            nbLongRange: 6 as i32,
            shortRange: xmlMS.as_ptr(),
            longRange: xmlML.as_ptr(),
        };
        init
    }
};
static mut xmlMcS: [xmlChSRange; 55] = [
    {
        let mut init = _xmlChSRange {
            low: 0x903 as i32 as u16,
            high: 0x903 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93e as i32 as u16,
            high: 0x940 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x949 as i32 as u16,
            high: 0x94c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x982 as i32 as u16,
            high: 0x983 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9be as i32 as u16,
            high: 0x9c0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9c7 as i32 as u16,
            high: 0x9c8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9cb as i32 as u16,
            high: 0x9cc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9d7 as i32 as u16,
            high: 0x9d7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa03 as i32 as u16,
            high: 0xa03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa3e as i32 as u16,
            high: 0xa40 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa83 as i32 as u16,
            high: 0xa83 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabe as i32 as u16,
            high: 0xac0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac9 as i32 as u16,
            high: 0xac9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xacb as i32 as u16,
            high: 0xacc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb02 as i32 as u16,
            high: 0xb03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3e as i32 as u16,
            high: 0xb3e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb40 as i32 as u16,
            high: 0xb40 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb47 as i32 as u16,
            high: 0xb48 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb4b as i32 as u16,
            high: 0xb4c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb57 as i32 as u16,
            high: 0xb57 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbbe as i32 as u16,
            high: 0xbbf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc1 as i32 as u16,
            high: 0xbc2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc6 as i32 as u16,
            high: 0xbc8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbca as i32 as u16,
            high: 0xbcc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbd7 as i32 as u16,
            high: 0xbd7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc01 as i32 as u16,
            high: 0xc03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc41 as i32 as u16,
            high: 0xc44 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc82 as i32 as u16,
            high: 0xc83 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbe as i32 as u16,
            high: 0xcbe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcc0 as i32 as u16,
            high: 0xcc4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcc7 as i32 as u16,
            high: 0xcc8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcca as i32 as u16,
            high: 0xccb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcd5 as i32 as u16,
            high: 0xcd6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd02 as i32 as u16,
            high: 0xd03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd3e as i32 as u16,
            high: 0xd40 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd46 as i32 as u16,
            high: 0xd48 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd4a as i32 as u16,
            high: 0xd4c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd57 as i32 as u16,
            high: 0xd57 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd82 as i32 as u16,
            high: 0xd83 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdcf as i32 as u16,
            high: 0xdd1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdd8 as i32 as u16,
            high: 0xddf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdf2 as i32 as u16,
            high: 0xdf3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3e as i32 as u16,
            high: 0xf3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf7f as i32 as u16,
            high: 0xf7f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x102c as i32 as u16,
            high: 0x102c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1031 as i32 as u16,
            high: 0x1031 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1038 as i32 as u16,
            high: 0x1038 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1056 as i32 as u16,
            high: 0x1057 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b6 as i32 as u16,
            high: 0x17b6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17be as i32 as u16,
            high: 0x17c5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17c7 as i32 as u16,
            high: 0x17c8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1923 as i32 as u16,
            high: 0x1926 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1929 as i32 as u16,
            high: 0x192b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1930 as i32 as u16,
            high: 0x1931 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1933 as i32 as u16,
            high: 0x1938 as i32 as u16,
        };
        init
    },
];
static mut xmlMcL: [xmlChLRange; 2] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d165 as i32 as u32,
            high: 0x1d166 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d16d as i32 as u32,
            high: 0x1d172 as i32 as u32,
        };
        init
    },
];
static mut xmlMcG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 55 as i32,
            nbLongRange: 2 as i32,
            shortRange: xmlMcS.as_ptr(),
            longRange: xmlMcL.as_ptr(),
        };
        init
    }
};
static mut xmlMnS: [xmlChSRange; 108] = [
    {
        let mut init = _xmlChSRange {
            low: 0x300 as i32 as u16,
            high: 0x357 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x35d as i32 as u16,
            high: 0x36f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x483 as i32 as u16,
            high: 0x486 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x591 as i32 as u16,
            high: 0x5a1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5a3 as i32 as u16,
            high: 0x5b9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5bb as i32 as u16,
            high: 0x5bd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5bf as i32 as u16,
            high: 0x5bf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c1 as i32 as u16,
            high: 0x5c2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c4 as i32 as u16,
            high: 0x5c4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x610 as i32 as u16,
            high: 0x615 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x64b as i32 as u16,
            high: 0x658 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x670 as i32 as u16,
            high: 0x670 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d6 as i32 as u16,
            high: 0x6dc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6df as i32 as u16,
            high: 0x6e4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e7 as i32 as u16,
            high: 0x6e8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ea as i32 as u16,
            high: 0x6ed as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x711 as i32 as u16,
            high: 0x711 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x730 as i32 as u16,
            high: 0x74a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7a6 as i32 as u16,
            high: 0x7b0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x901 as i32 as u16,
            high: 0x902 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93c as i32 as u16,
            high: 0x93c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x941 as i32 as u16,
            high: 0x948 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x94d as i32 as u16,
            high: 0x94d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x951 as i32 as u16,
            high: 0x954 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x962 as i32 as u16,
            high: 0x963 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x981 as i32 as u16,
            high: 0x981 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9bc as i32 as u16,
            high: 0x9bc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9c1 as i32 as u16,
            high: 0x9c4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9cd as i32 as u16,
            high: 0x9cd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9e2 as i32 as u16,
            high: 0x9e3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa01 as i32 as u16,
            high: 0xa02 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa3c as i32 as u16,
            high: 0xa3c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa41 as i32 as u16,
            high: 0xa42 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa47 as i32 as u16,
            high: 0xa48 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa4b as i32 as u16,
            high: 0xa4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa70 as i32 as u16,
            high: 0xa71 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa81 as i32 as u16,
            high: 0xa82 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabc as i32 as u16,
            high: 0xabc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac1 as i32 as u16,
            high: 0xac5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac7 as i32 as u16,
            high: 0xac8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xacd as i32 as u16,
            high: 0xacd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae2 as i32 as u16,
            high: 0xae3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb01 as i32 as u16,
            high: 0xb01 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3c as i32 as u16,
            high: 0xb3c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3f as i32 as u16,
            high: 0xb3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb41 as i32 as u16,
            high: 0xb43 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb4d as i32 as u16,
            high: 0xb4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb56 as i32 as u16,
            high: 0xb56 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb82 as i32 as u16,
            high: 0xb82 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc0 as i32 as u16,
            high: 0xbc0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbcd as i32 as u16,
            high: 0xbcd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc3e as i32 as u16,
            high: 0xc40 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc46 as i32 as u16,
            high: 0xc48 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc4a as i32 as u16,
            high: 0xc4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc55 as i32 as u16,
            high: 0xc56 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbc as i32 as u16,
            high: 0xcbc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbf as i32 as u16,
            high: 0xcbf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcc6 as i32 as u16,
            high: 0xcc6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xccc as i32 as u16,
            high: 0xccd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd41 as i32 as u16,
            high: 0xd43 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd4d as i32 as u16,
            high: 0xd4d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdca as i32 as u16,
            high: 0xdca as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdd2 as i32 as u16,
            high: 0xdd4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdd6 as i32 as u16,
            high: 0xdd6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe31 as i32 as u16,
            high: 0xe31 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe34 as i32 as u16,
            high: 0xe3a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe47 as i32 as u16,
            high: 0xe4e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb1 as i32 as u16,
            high: 0xeb1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb4 as i32 as u16,
            high: 0xeb9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xebb as i32 as u16,
            high: 0xebc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec8 as i32 as u16,
            high: 0xecd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf18 as i32 as u16,
            high: 0xf19 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf35 as i32 as u16,
            high: 0xf35 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf37 as i32 as u16,
            high: 0xf37 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf39 as i32 as u16,
            high: 0xf39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf71 as i32 as u16,
            high: 0xf7e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf80 as i32 as u16,
            high: 0xf84 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf86 as i32 as u16,
            high: 0xf87 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf90 as i32 as u16,
            high: 0xf97 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf99 as i32 as u16,
            high: 0xfbc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfc6 as i32 as u16,
            high: 0xfc6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x102d as i32 as u16,
            high: 0x1030 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1032 as i32 as u16,
            high: 0x1032 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1036 as i32 as u16,
            high: 0x1037 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1039 as i32 as u16,
            high: 0x1039 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1058 as i32 as u16,
            high: 0x1059 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1712 as i32 as u16,
            high: 0x1714 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1732 as i32 as u16,
            high: 0x1734 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1752 as i32 as u16,
            high: 0x1753 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1772 as i32 as u16,
            high: 0x1773 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b7 as i32 as u16,
            high: 0x17bd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17c6 as i32 as u16,
            high: 0x17c6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17c9 as i32 as u16,
            high: 0x17d3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17dd as i32 as u16,
            high: 0x17dd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x180b as i32 as u16,
            high: 0x180d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x18a9 as i32 as u16,
            high: 0x18a9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1920 as i32 as u16,
            high: 0x1922 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1927 as i32 as u16,
            high: 0x1928 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1932 as i32 as u16,
            high: 0x1932 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1939 as i32 as u16,
            high: 0x193b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20d0 as i32 as u16,
            high: 0x20dc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20e1 as i32 as u16,
            high: 0x20e1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20e5 as i32 as u16,
            high: 0x20ea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x302a as i32 as u16,
            high: 0x302f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3099 as i32 as u16,
            high: 0x309a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1e as i32 as u16,
            high: 0xfb1e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe00 as i32 as u16,
            high: 0xfe0f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe20 as i32 as u16,
            high: 0xfe23 as i32 as u16,
        };
        init
    },
];
static mut xmlMnL: [xmlChLRange; 5] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d167 as i32 as u32,
            high: 0x1d169 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d17b as i32 as u32,
            high: 0x1d182 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d185 as i32 as u32,
            high: 0x1d18b as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d1aa as i32 as u32,
            high: 0x1d1ad as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0100 as i32 as u32,
            high: 0xe01ef as i32 as u32,
        };
        init
    },
];
static mut xmlMnG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 108 as i32,
            nbLongRange: 5 as i32,
            shortRange: xmlMnS.as_ptr(),
            longRange: xmlMnL.as_ptr(),
        };
        init
    }
};
static mut xmlNS: [xmlChSRange; 42] = [
    {
        let mut init = _xmlChSRange {
            low: 0x30 as i32 as u16,
            high: 0x39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb2 as i32 as u16,
            high: 0xb3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9 as i32 as u16,
            high: 0xb9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc as i32 as u16,
            high: 0xbe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x660 as i32 as u16,
            high: 0x669 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6f0 as i32 as u16,
            high: 0x6f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x966 as i32 as u16,
            high: 0x96f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9e6 as i32 as u16,
            high: 0x9ef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f4 as i32 as u16,
            high: 0x9f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa66 as i32 as u16,
            high: 0xa6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae6 as i32 as u16,
            high: 0xaef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb66 as i32 as u16,
            high: 0xb6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbe7 as i32 as u16,
            high: 0xbf2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc66 as i32 as u16,
            high: 0xc6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xce6 as i32 as u16,
            high: 0xcef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd66 as i32 as u16,
            high: 0xd6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe50 as i32 as u16,
            high: 0xe59 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xed0 as i32 as u16,
            high: 0xed9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf20 as i32 as u16,
            high: 0xf33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1040 as i32 as u16,
            high: 0x1049 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1369 as i32 as u16,
            high: 0x137c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16ee as i32 as u16,
            high: 0x16f0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17e0 as i32 as u16,
            high: 0x17e9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17f0 as i32 as u16,
            high: 0x17f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1810 as i32 as u16,
            high: 0x1819 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1946 as i32 as u16,
            high: 0x194f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2070 as i32 as u16,
            high: 0x2070 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2074 as i32 as u16,
            high: 0x2079 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2080 as i32 as u16,
            high: 0x2089 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2153 as i32 as u16,
            high: 0x2183 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2460 as i32 as u16,
            high: 0x249b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x24ea as i32 as u16,
            high: 0x24ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2776 as i32 as u16,
            high: 0x2793 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3007 as i32 as u16,
            high: 0x3007 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3021 as i32 as u16,
            high: 0x3029 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3038 as i32 as u16,
            high: 0x303a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3192 as i32 as u16,
            high: 0x3195 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3220 as i32 as u16,
            high: 0x3229 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3251 as i32 as u16,
            high: 0x325f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3280 as i32 as u16,
            high: 0x3289 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x32b1 as i32 as u16,
            high: 0x32bf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff10 as i32 as u16,
            high: 0xff19 as i32 as u16,
        };
        init
    },
];
static mut xmlNL: [xmlChLRange; 5] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10107 as i32 as u32,
            high: 0x10133 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10320 as i32 as u32,
            high: 0x10323 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1034a as i32 as u32,
            high: 0x1034a as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x104a0 as i32 as u32,
            high: 0x104a9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7ce as i32 as u32,
            high: 0x1d7ff as i32 as u32,
        };
        init
    },
];
static mut xmlNG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 42 as i32,
            nbLongRange: 5 as i32,
            shortRange: xmlNS.as_ptr(),
            longRange: xmlNL.as_ptr(),
        };
        init
    }
};
static mut xmlNdS: [xmlChSRange; 21] = [
    {
        let mut init = _xmlChSRange {
            low: 0x30 as i32 as u16,
            high: 0x39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x660 as i32 as u16,
            high: 0x669 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6f0 as i32 as u16,
            high: 0x6f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x966 as i32 as u16,
            high: 0x96f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9e6 as i32 as u16,
            high: 0x9ef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa66 as i32 as u16,
            high: 0xa6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae6 as i32 as u16,
            high: 0xaef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb66 as i32 as u16,
            high: 0xb6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbe7 as i32 as u16,
            high: 0xbef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc66 as i32 as u16,
            high: 0xc6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xce6 as i32 as u16,
            high: 0xcef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd66 as i32 as u16,
            high: 0xd6f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe50 as i32 as u16,
            high: 0xe59 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xed0 as i32 as u16,
            high: 0xed9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf20 as i32 as u16,
            high: 0xf29 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1040 as i32 as u16,
            high: 0x1049 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1369 as i32 as u16,
            high: 0x1371 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17e0 as i32 as u16,
            high: 0x17e9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1810 as i32 as u16,
            high: 0x1819 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1946 as i32 as u16,
            high: 0x194f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff10 as i32 as u16,
            high: 0xff19 as i32 as u16,
        };
        init
    },
];
static mut xmlNdL: [xmlChLRange; 2] = [
    {
        let mut init = _xmlChLRange {
            low: 0x104a0 as i32 as u32,
            high: 0x104a9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7ce as i32 as u32,
            high: 0x1d7ff as i32 as u32,
        };
        init
    },
];
static mut xmlNdG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 21 as i32,
            nbLongRange: 2 as i32,
            shortRange: xmlNdS.as_ptr(),
            longRange: xmlNdL.as_ptr(),
        };
        init
    }
};
static mut xmlNoS: [xmlChSRange; 20] = [
    {
        let mut init = _xmlChSRange {
            low: 0xb2 as i32 as u16,
            high: 0xb3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9 as i32 as u16,
            high: 0xb9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc as i32 as u16,
            high: 0xbe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f4 as i32 as u16,
            high: 0x9f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf0 as i32 as u16,
            high: 0xbf2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf2a as i32 as u16,
            high: 0xf33 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1372 as i32 as u16,
            high: 0x137c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17f0 as i32 as u16,
            high: 0x17f9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2070 as i32 as u16,
            high: 0x2070 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2074 as i32 as u16,
            high: 0x2079 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2080 as i32 as u16,
            high: 0x2089 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2153 as i32 as u16,
            high: 0x215f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2460 as i32 as u16,
            high: 0x249b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x24ea as i32 as u16,
            high: 0x24ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2776 as i32 as u16,
            high: 0x2793 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3192 as i32 as u16,
            high: 0x3195 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3220 as i32 as u16,
            high: 0x3229 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3251 as i32 as u16,
            high: 0x325f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3280 as i32 as u16,
            high: 0x3289 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x32b1 as i32 as u16,
            high: 0x32bf as i32 as u16,
        };
        init
    },
];
static mut xmlNoL: [xmlChLRange; 2] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10107 as i32 as u32,
            high: 0x10133 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10320 as i32 as u32,
            high: 0x10323 as i32 as u32,
        };
        init
    },
];
static mut xmlNoG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 20 as i32,
            nbLongRange: 2 as i32,
            shortRange: xmlNoS.as_ptr(),
            longRange: xmlNoL.as_ptr(),
        };
        init
    }
};
static mut xmlPS: [xmlChSRange; 84] = [
    {
        let mut init = _xmlChSRange {
            low: 0x21 as i32 as u16,
            high: 0x23 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25 as i32 as u16,
            high: 0x2a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c as i32 as u16,
            high: 0x2f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3a as i32 as u16,
            high: 0x3b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f as i32 as u16,
            high: 0x40 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5b as i32 as u16,
            high: 0x5d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5f as i32 as u16,
            high: 0x5f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7b as i32 as u16,
            high: 0x7b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7d as i32 as u16,
            high: 0x7d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa1 as i32 as u16,
            high: 0xa1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xab as i32 as u16,
            high: 0xab as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb7 as i32 as u16,
            high: 0xb7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbb as i32 as u16,
            high: 0xbb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf as i32 as u16,
            high: 0xbf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x37e as i32 as u16,
            high: 0x37e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x387 as i32 as u16,
            high: 0x387 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x55a as i32 as u16,
            high: 0x55f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x589 as i32 as u16,
            high: 0x58a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5be as i32 as u16,
            high: 0x5be as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c0 as i32 as u16,
            high: 0x5c0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c3 as i32 as u16,
            high: 0x5c3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5f3 as i32 as u16,
            high: 0x5f4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60c as i32 as u16,
            high: 0x60d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x61b as i32 as u16,
            high: 0x61b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x61f as i32 as u16,
            high: 0x61f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x66a as i32 as u16,
            high: 0x66d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d4 as i32 as u16,
            high: 0x6d4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x700 as i32 as u16,
            high: 0x70d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x964 as i32 as u16,
            high: 0x965 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x970 as i32 as u16,
            high: 0x970 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdf4 as i32 as u16,
            high: 0xdf4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe4f as i32 as u16,
            high: 0xe4f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe5a as i32 as u16,
            high: 0xe5b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf04 as i32 as u16,
            high: 0xf12 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3a as i32 as u16,
            high: 0xf3d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf85 as i32 as u16,
            high: 0xf85 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x104a as i32 as u16,
            high: 0x104f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10fb as i32 as u16,
            high: 0x10fb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1361 as i32 as u16,
            high: 0x1368 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x166d as i32 as u16,
            high: 0x166e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x169b as i32 as u16,
            high: 0x169c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16eb as i32 as u16,
            high: 0x16ed as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1735 as i32 as u16,
            high: 0x1736 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d4 as i32 as u16,
            high: 0x17d6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d8 as i32 as u16,
            high: 0x17da as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1800 as i32 as u16,
            high: 0x180a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1944 as i32 as u16,
            high: 0x1945 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2010 as i32 as u16,
            high: 0x2027 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2030 as i32 as u16,
            high: 0x2043 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2045 as i32 as u16,
            high: 0x2051 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2053 as i32 as u16,
            high: 0x2054 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2057 as i32 as u16,
            high: 0x2057 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207d as i32 as u16,
            high: 0x207e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208d as i32 as u16,
            high: 0x208e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2329 as i32 as u16,
            high: 0x232a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b4 as i32 as u16,
            high: 0x23b6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2768 as i32 as u16,
            high: 0x2775 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27e6 as i32 as u16,
            high: 0x27eb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2983 as i32 as u16,
            high: 0x2998 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29d8 as i32 as u16,
            high: 0x29db as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29fc as i32 as u16,
            high: 0x29fd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3001 as i32 as u16,
            high: 0x3003 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3008 as i32 as u16,
            high: 0x3011 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3014 as i32 as u16,
            high: 0x301f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3030 as i32 as u16,
            high: 0x3030 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303d as i32 as u16,
            high: 0x303d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30a0 as i32 as u16,
            high: 0x30a0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30fb as i32 as u16,
            high: 0x30fb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd3e as i32 as u16,
            high: 0xfd3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe30 as i32 as u16,
            high: 0xfe52 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe54 as i32 as u16,
            high: 0xfe61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe63 as i32 as u16,
            high: 0xfe63 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe68 as i32 as u16,
            high: 0xfe68 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe6a as i32 as u16,
            high: 0xfe6b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff01 as i32 as u16,
            high: 0xff03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff05 as i32 as u16,
            high: 0xff0a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0c as i32 as u16,
            high: 0xff0f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1a as i32 as u16,
            high: 0xff1b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1f as i32 as u16,
            high: 0xff20 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3b as i32 as u16,
            high: 0xff3d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3f as i32 as u16,
            high: 0xff3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5b as i32 as u16,
            high: 0xff5b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5d as i32 as u16,
            high: 0xff5d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5f as i32 as u16,
            high: 0xff65 as i32 as u16,
        };
        init
    },
];
static mut xmlPL: [xmlChLRange; 2] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10100 as i32 as u32,
            high: 0x10101 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1039f as i32 as u32,
            high: 0x1039f as i32 as u32,
        };
        init
    },
];
static mut xmlPG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 84 as i32,
            nbLongRange: 2 as i32,
            shortRange: xmlPS.as_ptr(),
            longRange: xmlPL.as_ptr(),
        };
        init
    }
};
static mut xmlPdS: [xmlChSRange; 11] = [
    {
        let mut init = _xmlChSRange {
            low: 0x2d as i32 as u16,
            high: 0x2d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x58a as i32 as u16,
            high: 0x58a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1806 as i32 as u16,
            high: 0x1806 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2010 as i32 as u16,
            high: 0x2015 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x301c as i32 as u16,
            high: 0x301c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3030 as i32 as u16,
            high: 0x3030 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30a0 as i32 as u16,
            high: 0x30a0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe31 as i32 as u16,
            high: 0xfe32 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe58 as i32 as u16,
            high: 0xfe58 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe63 as i32 as u16,
            high: 0xfe63 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0d as i32 as u16,
            high: 0xff0d as i32 as u16,
        };
        init
    },
];
static mut xmlPdG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 11 as i32,
            nbLongRange: 0 as i32,
            shortRange: xmlPdS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlPeS: [xmlChSRange; 63] = [
    {
        let mut init = _xmlChSRange {
            low: 0x29 as i32 as u16,
            high: 0x29 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5d as i32 as u16,
            high: 0x5d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7d as i32 as u16,
            high: 0x7d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3b as i32 as u16,
            high: 0xf3b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3d as i32 as u16,
            high: 0xf3d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x169c as i32 as u16,
            high: 0x169c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2046 as i32 as u16,
            high: 0x2046 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207e as i32 as u16,
            high: 0x207e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208e as i32 as u16,
            high: 0x208e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x232a as i32 as u16,
            high: 0x232a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b5 as i32 as u16,
            high: 0x23b5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2769 as i32 as u16,
            high: 0x2769 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276b as i32 as u16,
            high: 0x276b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276d as i32 as u16,
            high: 0x276d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276f as i32 as u16,
            high: 0x276f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2771 as i32 as u16,
            high: 0x2771 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2773 as i32 as u16,
            high: 0x2773 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2775 as i32 as u16,
            high: 0x2775 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27e7 as i32 as u16,
            high: 0x27e7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27e9 as i32 as u16,
            high: 0x27e9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27eb as i32 as u16,
            high: 0x27eb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2984 as i32 as u16,
            high: 0x2984 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2986 as i32 as u16,
            high: 0x2986 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2988 as i32 as u16,
            high: 0x2988 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298a as i32 as u16,
            high: 0x298a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298c as i32 as u16,
            high: 0x298c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298e as i32 as u16,
            high: 0x298e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2990 as i32 as u16,
            high: 0x2990 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2992 as i32 as u16,
            high: 0x2992 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2994 as i32 as u16,
            high: 0x2994 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2996 as i32 as u16,
            high: 0x2996 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2998 as i32 as u16,
            high: 0x2998 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29d9 as i32 as u16,
            high: 0x29d9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29db as i32 as u16,
            high: 0x29db as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29fd as i32 as u16,
            high: 0x29fd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3009 as i32 as u16,
            high: 0x3009 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300b as i32 as u16,
            high: 0x300b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300d as i32 as u16,
            high: 0x300d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300f as i32 as u16,
            high: 0x300f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3011 as i32 as u16,
            high: 0x3011 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3015 as i32 as u16,
            high: 0x3015 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3017 as i32 as u16,
            high: 0x3017 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3019 as i32 as u16,
            high: 0x3019 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x301b as i32 as u16,
            high: 0x301b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x301e as i32 as u16,
            high: 0x301f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd3f as i32 as u16,
            high: 0xfd3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe36 as i32 as u16,
            high: 0xfe36 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe38 as i32 as u16,
            high: 0xfe38 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3a as i32 as u16,
            high: 0xfe3a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3c as i32 as u16,
            high: 0xfe3c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3e as i32 as u16,
            high: 0xfe3e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe40 as i32 as u16,
            high: 0xfe40 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe42 as i32 as u16,
            high: 0xfe42 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe44 as i32 as u16,
            high: 0xfe44 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe48 as i32 as u16,
            high: 0xfe48 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5a as i32 as u16,
            high: 0xfe5a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5c as i32 as u16,
            high: 0xfe5c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5e as i32 as u16,
            high: 0xfe5e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff09 as i32 as u16,
            high: 0xff09 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3d as i32 as u16,
            high: 0xff3d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5d as i32 as u16,
            high: 0xff5d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff60 as i32 as u16,
            high: 0xff60 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff63 as i32 as u16,
            high: 0xff63 as i32 as u16,
        };
        init
    },
];
static mut xmlPeG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 63 as i32,
            nbLongRange: 0 as i32,
            shortRange: xmlPeS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlPoS: [xmlChSRange; 72] = [
    {
        let mut init = _xmlChSRange {
            low: 0x21 as i32 as u16,
            high: 0x23 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25 as i32 as u16,
            high: 0x27 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2a as i32 as u16,
            high: 0x2a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c as i32 as u16,
            high: 0x2c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e as i32 as u16,
            high: 0x2f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3a as i32 as u16,
            high: 0x3b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f as i32 as u16,
            high: 0x40 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c as i32 as u16,
            high: 0x5c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa1 as i32 as u16,
            high: 0xa1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb7 as i32 as u16,
            high: 0xb7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf as i32 as u16,
            high: 0xbf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x37e as i32 as u16,
            high: 0x37e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x387 as i32 as u16,
            high: 0x387 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x55a as i32 as u16,
            high: 0x55f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x589 as i32 as u16,
            high: 0x589 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5be as i32 as u16,
            high: 0x5be as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c0 as i32 as u16,
            high: 0x5c0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c3 as i32 as u16,
            high: 0x5c3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5f3 as i32 as u16,
            high: 0x5f4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60c as i32 as u16,
            high: 0x60d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x61b as i32 as u16,
            high: 0x61b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x61f as i32 as u16,
            high: 0x61f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x66a as i32 as u16,
            high: 0x66d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d4 as i32 as u16,
            high: 0x6d4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x700 as i32 as u16,
            high: 0x70d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x964 as i32 as u16,
            high: 0x965 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x970 as i32 as u16,
            high: 0x970 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdf4 as i32 as u16,
            high: 0xdf4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe4f as i32 as u16,
            high: 0xe4f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe5a as i32 as u16,
            high: 0xe5b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf04 as i32 as u16,
            high: 0xf12 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf85 as i32 as u16,
            high: 0xf85 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x104a as i32 as u16,
            high: 0x104f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10fb as i32 as u16,
            high: 0x10fb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1361 as i32 as u16,
            high: 0x1368 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x166d as i32 as u16,
            high: 0x166e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16eb as i32 as u16,
            high: 0x16ed as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1735 as i32 as u16,
            high: 0x1736 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d4 as i32 as u16,
            high: 0x17d6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d8 as i32 as u16,
            high: 0x17da as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1800 as i32 as u16,
            high: 0x1805 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1807 as i32 as u16,
            high: 0x180a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1944 as i32 as u16,
            high: 0x1945 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2016 as i32 as u16,
            high: 0x2017 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2020 as i32 as u16,
            high: 0x2027 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2030 as i32 as u16,
            high: 0x2038 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x203b as i32 as u16,
            high: 0x203e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2041 as i32 as u16,
            high: 0x2043 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2047 as i32 as u16,
            high: 0x2051 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2053 as i32 as u16,
            high: 0x2053 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2057 as i32 as u16,
            high: 0x2057 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b6 as i32 as u16,
            high: 0x23b6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3001 as i32 as u16,
            high: 0x3003 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303d as i32 as u16,
            high: 0x303d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe30 as i32 as u16,
            high: 0xfe30 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe45 as i32 as u16,
            high: 0xfe46 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe49 as i32 as u16,
            high: 0xfe4c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe50 as i32 as u16,
            high: 0xfe52 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe54 as i32 as u16,
            high: 0xfe57 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5f as i32 as u16,
            high: 0xfe61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe68 as i32 as u16,
            high: 0xfe68 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe6a as i32 as u16,
            high: 0xfe6b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff01 as i32 as u16,
            high: 0xff03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff05 as i32 as u16,
            high: 0xff07 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0a as i32 as u16,
            high: 0xff0a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0c as i32 as u16,
            high: 0xff0c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0e as i32 as u16,
            high: 0xff0f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1a as i32 as u16,
            high: 0xff1b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1f as i32 as u16,
            high: 0xff20 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3c as i32 as u16,
            high: 0xff3c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff61 as i32 as u16,
            high: 0xff61 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff64 as i32 as u16,
            high: 0xff64 as i32 as u16,
        };
        init
    },
];
static mut xmlPoL: [xmlChLRange; 2] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10100 as i32 as u32,
            high: 0x10101 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1039f as i32 as u32,
            high: 0x1039f as i32 as u32,
        };
        init
    },
];
static mut xmlPoG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 72 as i32,
            nbLongRange: 2 as i32,
            shortRange: xmlPoS.as_ptr(),
            longRange: xmlPoL.as_ptr(),
        };
        init
    }
};
static mut xmlPsS: [xmlChSRange; 65] = [
    {
        let mut init = _xmlChSRange {
            low: 0x28 as i32 as u16,
            high: 0x28 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5b as i32 as u16,
            high: 0x5b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7b as i32 as u16,
            high: 0x7b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3a as i32 as u16,
            high: 0xf3a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3c as i32 as u16,
            high: 0xf3c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x169b as i32 as u16,
            high: 0x169b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x201a as i32 as u16,
            high: 0x201a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x201e as i32 as u16,
            high: 0x201e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2045 as i32 as u16,
            high: 0x2045 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207d as i32 as u16,
            high: 0x207d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208d as i32 as u16,
            high: 0x208d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2329 as i32 as u16,
            high: 0x2329 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b4 as i32 as u16,
            high: 0x23b4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2768 as i32 as u16,
            high: 0x2768 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276a as i32 as u16,
            high: 0x276a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276c as i32 as u16,
            high: 0x276c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276e as i32 as u16,
            high: 0x276e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2770 as i32 as u16,
            high: 0x2770 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2772 as i32 as u16,
            high: 0x2772 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2774 as i32 as u16,
            high: 0x2774 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27e6 as i32 as u16,
            high: 0x27e6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27e8 as i32 as u16,
            high: 0x27e8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27ea as i32 as u16,
            high: 0x27ea as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2983 as i32 as u16,
            high: 0x2983 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2985 as i32 as u16,
            high: 0x2985 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2987 as i32 as u16,
            high: 0x2987 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2989 as i32 as u16,
            high: 0x2989 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298b as i32 as u16,
            high: 0x298b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298d as i32 as u16,
            high: 0x298d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298f as i32 as u16,
            high: 0x298f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2991 as i32 as u16,
            high: 0x2991 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2993 as i32 as u16,
            high: 0x2993 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2995 as i32 as u16,
            high: 0x2995 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2997 as i32 as u16,
            high: 0x2997 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29d8 as i32 as u16,
            high: 0x29d8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29da as i32 as u16,
            high: 0x29da as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29fc as i32 as u16,
            high: 0x29fc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3008 as i32 as u16,
            high: 0x3008 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300a as i32 as u16,
            high: 0x300a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300c as i32 as u16,
            high: 0x300c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300e as i32 as u16,
            high: 0x300e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3010 as i32 as u16,
            high: 0x3010 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3014 as i32 as u16,
            high: 0x3014 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3016 as i32 as u16,
            high: 0x3016 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3018 as i32 as u16,
            high: 0x3018 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x301a as i32 as u16,
            high: 0x301a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x301d as i32 as u16,
            high: 0x301d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd3e as i32 as u16,
            high: 0xfd3e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe35 as i32 as u16,
            high: 0xfe35 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe37 as i32 as u16,
            high: 0xfe37 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe39 as i32 as u16,
            high: 0xfe39 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3b as i32 as u16,
            high: 0xfe3b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3d as i32 as u16,
            high: 0xfe3d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3f as i32 as u16,
            high: 0xfe3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe41 as i32 as u16,
            high: 0xfe41 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe43 as i32 as u16,
            high: 0xfe43 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe47 as i32 as u16,
            high: 0xfe47 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe59 as i32 as u16,
            high: 0xfe59 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5b as i32 as u16,
            high: 0xfe5b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5d as i32 as u16,
            high: 0xfe5d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff08 as i32 as u16,
            high: 0xff08 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3b as i32 as u16,
            high: 0xff3b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5b as i32 as u16,
            high: 0xff5b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5f as i32 as u16,
            high: 0xff5f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff62 as i32 as u16,
            high: 0xff62 as i32 as u16,
        };
        init
    },
];
static mut xmlPsG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 65 as i32,
            nbLongRange: 0 as i32,
            shortRange: xmlPsS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlSS: [xmlChSRange; 133] = [
    {
        let mut init = _xmlChSRange {
            low: 0x24 as i32 as u16,
            high: 0x24 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2b as i32 as u16,
            high: 0x2b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3c as i32 as u16,
            high: 0x3e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5e as i32 as u16,
            high: 0x5e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60 as i32 as u16,
            high: 0x60 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7c as i32 as u16,
            high: 0x7c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7e as i32 as u16,
            high: 0x7e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa2 as i32 as u16,
            high: 0xa9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac as i32 as u16,
            high: 0xac as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae as i32 as u16,
            high: 0xb1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb4 as i32 as u16,
            high: 0xb4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb6 as i32 as u16,
            high: 0xb6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb8 as i32 as u16,
            high: 0xb8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd7 as i32 as u16,
            high: 0xd7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf7 as i32 as u16,
            high: 0xf7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c2 as i32 as u16,
            high: 0x2c5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2d2 as i32 as u16,
            high: 0x2df as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e5 as i32 as u16,
            high: 0x2ed as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ef as i32 as u16,
            high: 0x2ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x374 as i32 as u16,
            high: 0x375 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x384 as i32 as u16,
            high: 0x385 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f6 as i32 as u16,
            high: 0x3f6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x482 as i32 as u16,
            high: 0x482 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60e as i32 as u16,
            high: 0x60f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e9 as i32 as u16,
            high: 0x6e9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6fd as i32 as u16,
            high: 0x6fe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f2 as i32 as u16,
            high: 0x9f3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9fa as i32 as u16,
            high: 0x9fa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaf1 as i32 as u16,
            high: 0xaf1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb70 as i32 as u16,
            high: 0xb70 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf3 as i32 as u16,
            high: 0xbfa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe3f as i32 as u16,
            high: 0xe3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf01 as i32 as u16,
            high: 0xf03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf13 as i32 as u16,
            high: 0xf17 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf1a as i32 as u16,
            high: 0xf1f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf34 as i32 as u16,
            high: 0xf34 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf36 as i32 as u16,
            high: 0xf36 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf38 as i32 as u16,
            high: 0xf38 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfbe as i32 as u16,
            high: 0xfc5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfc7 as i32 as u16,
            high: 0xfcc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfcf as i32 as u16,
            high: 0xfcf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17db as i32 as u16,
            high: 0x17db as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1940 as i32 as u16,
            high: 0x1940 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x19e0 as i32 as u16,
            high: 0x19ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbd as i32 as u16,
            high: 0x1fbd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbf as i32 as u16,
            high: 0x1fc1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fcd as i32 as u16,
            high: 0x1fcf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fdd as i32 as u16,
            high: 0x1fdf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fed as i32 as u16,
            high: 0x1fef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ffd as i32 as u16,
            high: 0x1ffe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2044 as i32 as u16,
            high: 0x2044 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2052 as i32 as u16,
            high: 0x2052 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207a as i32 as u16,
            high: 0x207c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208a as i32 as u16,
            high: 0x208c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20a0 as i32 as u16,
            high: 0x20b1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2100 as i32 as u16,
            high: 0x2101 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2103 as i32 as u16,
            high: 0x2106 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2108 as i32 as u16,
            high: 0x2109 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2114 as i32 as u16,
            high: 0x2114 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2116 as i32 as u16,
            high: 0x2118 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x211e as i32 as u16,
            high: 0x2123 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2125 as i32 as u16,
            high: 0x2125 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2127 as i32 as u16,
            high: 0x2127 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2129 as i32 as u16,
            high: 0x2129 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212e as i32 as u16,
            high: 0x212e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2132 as i32 as u16,
            high: 0x2132 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213a as i32 as u16,
            high: 0x213b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2140 as i32 as u16,
            high: 0x2144 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x214a as i32 as u16,
            high: 0x214b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2190 as i32 as u16,
            high: 0x2328 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x232b as i32 as u16,
            high: 0x23b3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b7 as i32 as u16,
            high: 0x23d0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2400 as i32 as u16,
            high: 0x2426 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2440 as i32 as u16,
            high: 0x244a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x249c as i32 as u16,
            high: 0x24e9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2500 as i32 as u16,
            high: 0x2617 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2619 as i32 as u16,
            high: 0x267d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2680 as i32 as u16,
            high: 0x2691 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x26a0 as i32 as u16,
            high: 0x26a1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2701 as i32 as u16,
            high: 0x2704 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2706 as i32 as u16,
            high: 0x2709 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x270c as i32 as u16,
            high: 0x2727 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2729 as i32 as u16,
            high: 0x274b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x274d as i32 as u16,
            high: 0x274d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x274f as i32 as u16,
            high: 0x2752 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2756 as i32 as u16,
            high: 0x2756 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2758 as i32 as u16,
            high: 0x275e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2761 as i32 as u16,
            high: 0x2767 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2794 as i32 as u16,
            high: 0x2794 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2798 as i32 as u16,
            high: 0x27af as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27b1 as i32 as u16,
            high: 0x27be as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27d0 as i32 as u16,
            high: 0x27e5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27f0 as i32 as u16,
            high: 0x2982 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2999 as i32 as u16,
            high: 0x29d7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29dc as i32 as u16,
            high: 0x29fb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29fe as i32 as u16,
            high: 0x2b0d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e80 as i32 as u16,
            high: 0x2e99 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e9b as i32 as u16,
            high: 0x2ef3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2f00 as i32 as u16,
            high: 0x2fd5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ff0 as i32 as u16,
            high: 0x2ffb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3004 as i32 as u16,
            high: 0x3004 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3012 as i32 as u16,
            high: 0x3013 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3020 as i32 as u16,
            high: 0x3020 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3036 as i32 as u16,
            high: 0x3037 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303e as i32 as u16,
            high: 0x303f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309b as i32 as u16,
            high: 0x309c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3190 as i32 as u16,
            high: 0x3191 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3196 as i32 as u16,
            high: 0x319f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3200 as i32 as u16,
            high: 0x321e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x322a as i32 as u16,
            high: 0x3243 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3250 as i32 as u16,
            high: 0x3250 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3260 as i32 as u16,
            high: 0x327d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x327f as i32 as u16,
            high: 0x327f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x328a as i32 as u16,
            high: 0x32b0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x32c0 as i32 as u16,
            high: 0x32fe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3300 as i32 as u16,
            high: 0x33ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4dc0 as i32 as u16,
            high: 0x4dff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa490 as i32 as u16,
            high: 0xa4c6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb29 as i32 as u16,
            high: 0xfb29 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfdfc as i32 as u16,
            high: 0xfdfd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe62 as i32 as u16,
            high: 0xfe62 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe64 as i32 as u16,
            high: 0xfe66 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe69 as i32 as u16,
            high: 0xfe69 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff04 as i32 as u16,
            high: 0xff04 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0b as i32 as u16,
            high: 0xff0b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1c as i32 as u16,
            high: 0xff1e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3e as i32 as u16,
            high: 0xff3e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff40 as i32 as u16,
            high: 0xff40 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5c as i32 as u16,
            high: 0xff5c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5e as i32 as u16,
            high: 0xff5e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe0 as i32 as u16,
            high: 0xffe6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe8 as i32 as u16,
            high: 0xffee as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfffc as i32 as u16,
            high: 0xfffd as i32 as u16,
        };
        init
    },
];
static mut xmlSL: [xmlChLRange; 20] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10102 as i32 as u32,
            high: 0x10102 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10137 as i32 as u32,
            high: 0x1013f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d000 as i32 as u32,
            high: 0x1d0f5 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d100 as i32 as u32,
            high: 0x1d126 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d12a as i32 as u32,
            high: 0x1d164 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d16a as i32 as u32,
            high: 0x1d16c as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d183 as i32 as u32,
            high: 0x1d184 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d18c as i32 as u32,
            high: 0x1d1a9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d1ae as i32 as u32,
            high: 0x1d1dd as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d300 as i32 as u32,
            high: 0x1d356 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6c1 as i32 as u32,
            high: 0x1d6c1 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6db as i32 as u32,
            high: 0x1d6db as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6fb as i32 as u32,
            high: 0x1d6fb as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d715 as i32 as u32,
            high: 0x1d715 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d735 as i32 as u32,
            high: 0x1d735 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d74f as i32 as u32,
            high: 0x1d74f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d76f as i32 as u32,
            high: 0x1d76f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d789 as i32 as u32,
            high: 0x1d789 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7a9 as i32 as u32,
            high: 0x1d7a9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7c3 as i32 as u32,
            high: 0x1d7c3 as i32 as u32,
        };
        init
    },
];
static mut xmlSG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 133 as i32,
            nbLongRange: 20 as i32,
            shortRange: xmlSS.as_ptr(),
            longRange: xmlSL.as_ptr(),
        };
        init
    }
};
static mut xmlScS: [xmlChSRange; 13] = [
    {
        let mut init = _xmlChSRange {
            low: 0x24 as i32 as u16,
            high: 0x24 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa2 as i32 as u16,
            high: 0xa5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f2 as i32 as u16,
            high: 0x9f3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaf1 as i32 as u16,
            high: 0xaf1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf9 as i32 as u16,
            high: 0xbf9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe3f as i32 as u16,
            high: 0xe3f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17db as i32 as u16,
            high: 0x17db as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20a0 as i32 as u16,
            high: 0x20b1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfdfc as i32 as u16,
            high: 0xfdfc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe69 as i32 as u16,
            high: 0xfe69 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff04 as i32 as u16,
            high: 0xff04 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe0 as i32 as u16,
            high: 0xffe1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe5 as i32 as u16,
            high: 0xffe6 as i32 as u16,
        };
        init
    },
];
static mut xmlScG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 13 as i32,
            nbLongRange: 0 as i32,
            shortRange: xmlScS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlSkS: [xmlChSRange; 22] = [
    {
        let mut init = _xmlChSRange {
            low: 0x5e as i32 as u16,
            high: 0x5e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60 as i32 as u16,
            high: 0x60 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa8 as i32 as u16,
            high: 0xa8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaf as i32 as u16,
            high: 0xaf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb4 as i32 as u16,
            high: 0xb4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb8 as i32 as u16,
            high: 0xb8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c2 as i32 as u16,
            high: 0x2c5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2d2 as i32 as u16,
            high: 0x2df as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e5 as i32 as u16,
            high: 0x2ed as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ef as i32 as u16,
            high: 0x2ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x374 as i32 as u16,
            high: 0x375 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x384 as i32 as u16,
            high: 0x385 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbd as i32 as u16,
            high: 0x1fbd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbf as i32 as u16,
            high: 0x1fc1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fcd as i32 as u16,
            high: 0x1fcf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fdd as i32 as u16,
            high: 0x1fdf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fed as i32 as u16,
            high: 0x1fef as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ffd as i32 as u16,
            high: 0x1ffe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309b as i32 as u16,
            high: 0x309c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3e as i32 as u16,
            high: 0xff3e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff40 as i32 as u16,
            high: 0xff40 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe3 as i32 as u16,
            high: 0xffe3 as i32 as u16,
        };
        init
    },
];
static mut xmlSkG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 22 as i32,
            nbLongRange: 0 as i32,
            shortRange: xmlSkS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlSmS: [xmlChSRange; 48] = [
    {
        let mut init = _xmlChSRange {
            low: 0x2b as i32 as u16,
            high: 0x2b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3c as i32 as u16,
            high: 0x3e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7c as i32 as u16,
            high: 0x7c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7e as i32 as u16,
            high: 0x7e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac as i32 as u16,
            high: 0xac as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb1 as i32 as u16,
            high: 0xb1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd7 as i32 as u16,
            high: 0xd7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf7 as i32 as u16,
            high: 0xf7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f6 as i32 as u16,
            high: 0x3f6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2044 as i32 as u16,
            high: 0x2044 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2052 as i32 as u16,
            high: 0x2052 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207a as i32 as u16,
            high: 0x207c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208a as i32 as u16,
            high: 0x208c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2140 as i32 as u16,
            high: 0x2144 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x214b as i32 as u16,
            high: 0x214b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2190 as i32 as u16,
            high: 0x2194 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x219a as i32 as u16,
            high: 0x219b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a0 as i32 as u16,
            high: 0x21a0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a3 as i32 as u16,
            high: 0x21a3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a6 as i32 as u16,
            high: 0x21a6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21ae as i32 as u16,
            high: 0x21ae as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21ce as i32 as u16,
            high: 0x21cf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d2 as i32 as u16,
            high: 0x21d2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d4 as i32 as u16,
            high: 0x21d4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21f4 as i32 as u16,
            high: 0x22ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2308 as i32 as u16,
            high: 0x230b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2320 as i32 as u16,
            high: 0x2321 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x237c as i32 as u16,
            high: 0x237c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x239b as i32 as u16,
            high: 0x23b3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25b7 as i32 as u16,
            high: 0x25b7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25c1 as i32 as u16,
            high: 0x25c1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25f8 as i32 as u16,
            high: 0x25ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x266f as i32 as u16,
            high: 0x266f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27d0 as i32 as u16,
            high: 0x27e5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27f0 as i32 as u16,
            high: 0x27ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2900 as i32 as u16,
            high: 0x2982 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2999 as i32 as u16,
            high: 0x29d7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29dc as i32 as u16,
            high: 0x29fb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29fe as i32 as u16,
            high: 0x2aff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb29 as i32 as u16,
            high: 0xfb29 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe62 as i32 as u16,
            high: 0xfe62 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe64 as i32 as u16,
            high: 0xfe66 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0b as i32 as u16,
            high: 0xff0b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1c as i32 as u16,
            high: 0xff1e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5c as i32 as u16,
            high: 0xff5c as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5e as i32 as u16,
            high: 0xff5e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe2 as i32 as u16,
            high: 0xffe2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe9 as i32 as u16,
            high: 0xffec as i32 as u16,
        };
        init
    },
];
static mut xmlSmL: [xmlChLRange; 10] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d6c1 as i32 as u32,
            high: 0x1d6c1 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6db as i32 as u32,
            high: 0x1d6db as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6fb as i32 as u32,
            high: 0x1d6fb as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d715 as i32 as u32,
            high: 0x1d715 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d735 as i32 as u32,
            high: 0x1d735 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d74f as i32 as u32,
            high: 0x1d74f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d76f as i32 as u32,
            high: 0x1d76f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d789 as i32 as u32,
            high: 0x1d789 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7a9 as i32 as u32,
            high: 0x1d7a9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7c3 as i32 as u32,
            high: 0x1d7c3 as i32 as u32,
        };
        init
    },
];
static mut xmlSmG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 48 as i32,
            nbLongRange: 10 as i32,
            shortRange: xmlSmS.as_ptr(),
            longRange: xmlSmL.as_ptr(),
        };
        init
    }
};
static mut xmlSoS: [xmlChSRange; 103] = [
    {
        let mut init = _xmlChSRange {
            low: 0xa6 as i32 as u16,
            high: 0xa7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa9 as i32 as u16,
            high: 0xa9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae as i32 as u16,
            high: 0xae as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb0 as i32 as u16,
            high: 0xb0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb6 as i32 as u16,
            high: 0xb6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x482 as i32 as u16,
            high: 0x482 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60e as i32 as u16,
            high: 0x60f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e9 as i32 as u16,
            high: 0x6e9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6fd as i32 as u16,
            high: 0x6fe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9fa as i32 as u16,
            high: 0x9fa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb70 as i32 as u16,
            high: 0xb70 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf3 as i32 as u16,
            high: 0xbf8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbfa as i32 as u16,
            high: 0xbfa as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf01 as i32 as u16,
            high: 0xf03 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf13 as i32 as u16,
            high: 0xf17 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf1a as i32 as u16,
            high: 0xf1f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf34 as i32 as u16,
            high: 0xf34 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf36 as i32 as u16,
            high: 0xf36 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf38 as i32 as u16,
            high: 0xf38 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfbe as i32 as u16,
            high: 0xfc5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfc7 as i32 as u16,
            high: 0xfcc as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfcf as i32 as u16,
            high: 0xfcf as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1940 as i32 as u16,
            high: 0x1940 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x19e0 as i32 as u16,
            high: 0x19ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2100 as i32 as u16,
            high: 0x2101 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2103 as i32 as u16,
            high: 0x2106 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2108 as i32 as u16,
            high: 0x2109 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2114 as i32 as u16,
            high: 0x2114 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2116 as i32 as u16,
            high: 0x2118 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x211e as i32 as u16,
            high: 0x2123 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2125 as i32 as u16,
            high: 0x2125 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2127 as i32 as u16,
            high: 0x2127 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2129 as i32 as u16,
            high: 0x2129 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212e as i32 as u16,
            high: 0x212e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2132 as i32 as u16,
            high: 0x2132 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213a as i32 as u16,
            high: 0x213b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x214a as i32 as u16,
            high: 0x214a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2195 as i32 as u16,
            high: 0x2199 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x219c as i32 as u16,
            high: 0x219f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a1 as i32 as u16,
            high: 0x21a2 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a4 as i32 as u16,
            high: 0x21a5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a7 as i32 as u16,
            high: 0x21ad as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21af as i32 as u16,
            high: 0x21cd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d0 as i32 as u16,
            high: 0x21d1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d3 as i32 as u16,
            high: 0x21d3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d5 as i32 as u16,
            high: 0x21f3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2300 as i32 as u16,
            high: 0x2307 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x230c as i32 as u16,
            high: 0x231f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2322 as i32 as u16,
            high: 0x2328 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x232b as i32 as u16,
            high: 0x237b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x237d as i32 as u16,
            high: 0x239a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b7 as i32 as u16,
            high: 0x23d0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2400 as i32 as u16,
            high: 0x2426 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2440 as i32 as u16,
            high: 0x244a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x249c as i32 as u16,
            high: 0x24e9 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2500 as i32 as u16,
            high: 0x25b6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25b8 as i32 as u16,
            high: 0x25c0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25c2 as i32 as u16,
            high: 0x25f7 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2600 as i32 as u16,
            high: 0x2617 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2619 as i32 as u16,
            high: 0x266e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2670 as i32 as u16,
            high: 0x267d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2680 as i32 as u16,
            high: 0x2691 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x26a0 as i32 as u16,
            high: 0x26a1 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2701 as i32 as u16,
            high: 0x2704 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2706 as i32 as u16,
            high: 0x2709 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x270c as i32 as u16,
            high: 0x2727 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2729 as i32 as u16,
            high: 0x274b as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x274d as i32 as u16,
            high: 0x274d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x274f as i32 as u16,
            high: 0x2752 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2756 as i32 as u16,
            high: 0x2756 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2758 as i32 as u16,
            high: 0x275e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2761 as i32 as u16,
            high: 0x2767 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2794 as i32 as u16,
            high: 0x2794 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2798 as i32 as u16,
            high: 0x27af as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27b1 as i32 as u16,
            high: 0x27be as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2800 as i32 as u16,
            high: 0x28ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2b00 as i32 as u16,
            high: 0x2b0d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e80 as i32 as u16,
            high: 0x2e99 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e9b as i32 as u16,
            high: 0x2ef3 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2f00 as i32 as u16,
            high: 0x2fd5 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ff0 as i32 as u16,
            high: 0x2ffb as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3004 as i32 as u16,
            high: 0x3004 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3012 as i32 as u16,
            high: 0x3013 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3020 as i32 as u16,
            high: 0x3020 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3036 as i32 as u16,
            high: 0x3037 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303e as i32 as u16,
            high: 0x303f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3190 as i32 as u16,
            high: 0x3191 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3196 as i32 as u16,
            high: 0x319f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3200 as i32 as u16,
            high: 0x321e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x322a as i32 as u16,
            high: 0x3243 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3250 as i32 as u16,
            high: 0x3250 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3260 as i32 as u16,
            high: 0x327d as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x327f as i32 as u16,
            high: 0x327f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x328a as i32 as u16,
            high: 0x32b0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x32c0 as i32 as u16,
            high: 0x32fe as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3300 as i32 as u16,
            high: 0x33ff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4dc0 as i32 as u16,
            high: 0x4dff as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa490 as i32 as u16,
            high: 0xa4c6 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfdfd as i32 as u16,
            high: 0xfdfd as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe4 as i32 as u16,
            high: 0xffe4 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe8 as i32 as u16,
            high: 0xffe8 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffed as i32 as u16,
            high: 0xffee as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfffc as i32 as u16,
            high: 0xfffd as i32 as u16,
        };
        init
    },
];
static mut xmlSoL: [xmlChLRange; 10] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10102 as i32 as u32,
            high: 0x10102 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10137 as i32 as u32,
            high: 0x1013f as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d000 as i32 as u32,
            high: 0x1d0f5 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d100 as i32 as u32,
            high: 0x1d126 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d12a as i32 as u32,
            high: 0x1d164 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d16a as i32 as u32,
            high: 0x1d16c as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d183 as i32 as u32,
            high: 0x1d184 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d18c as i32 as u32,
            high: 0x1d1a9 as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d1ae as i32 as u32,
            high: 0x1d1dd as i32 as u32,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d300 as i32 as u32,
            high: 0x1d356 as i32 as u32,
        };
        init
    },
];
static mut xmlSoG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 103 as i32,
            nbLongRange: 10 as i32,
            shortRange: xmlSoS.as_ptr(),
            longRange: xmlSoL.as_ptr(),
        };
        init
    }
};
static mut xmlZS: [xmlChSRange; 9] = [
    {
        let mut init = _xmlChSRange {
            low: 0x20 as i32 as u16,
            high: 0x20 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa0 as i32 as u16,
            high: 0xa0 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1680 as i32 as u16,
            high: 0x1680 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x180e as i32 as u16,
            high: 0x180e as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2000 as i32 as u16,
            high: 0x200a as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2028 as i32 as u16,
            high: 0x2029 as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x202f as i32 as u16,
            high: 0x202f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x205f as i32 as u16,
            high: 0x205f as i32 as u16,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3000 as i32 as u16,
            high: 0x3000 as i32 as u16,
        };
        init
    },
];
static mut xmlZG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 9 as i32,
            nbLongRange: 0 as i32,
            shortRange: xmlZS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlUnicodeBlockTbl: xmlUnicodeNameTable = unsafe {
    {
        let mut init = xmlUnicodeNameTable {
            table: xmlUnicodeBlocks.as_ptr(),
            numentries: 128 as i32,
        };
        init
    }
};
static mut xmlUnicodeCatTbl: xmlUnicodeNameTable = unsafe {
    {
        let mut init = xmlUnicodeNameTable {
            table: xmlUnicodeCats.as_ptr(),
            numentries: 36 as i32,
        };
        init
    }
};
extern "C" fn xmlUnicodeLookup(
    mut tptr: *const xmlUnicodeNameTable,
    mut tname: *const i8,
) -> Option<xmlIntFunc> {
    let mut low: i32 = 0;
    let mut high: i32 = 0;
    let mut mid: i32 = 0;
    let mut cmp: i32 = 0;
    let mut sptr: *const xmlUnicodeRange = 0 as *const xmlUnicodeRange;
    if tptr.is_null() || tname.is_null() {
        return None;
    }
    low = 0 as i32;
    high = (unsafe { (*tptr).numentries }) - 1 as i32;
    sptr = unsafe { (*tptr).table };
    while low <= high {
        mid = (low + high) / 2 as i32;
        cmp = unsafe { strcmp(tname, (*sptr.offset(mid as isize)).rangename) };
        if cmp == 0 as i32 {
            return unsafe { (*sptr.offset(mid as isize)).func };
        }
        if cmp < 0 as i32 {
            high = mid - 1 as i32;
        } else {
            low = mid + 1 as i32;
        }
    }
    return None;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsAegeanNumbers(mut code: i32) -> i32 {
    return (code >= 0x10100 as i32 && code <= 0x1013f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsAlphabeticPresentationForms(mut code: i32) -> i32 {
    return (code >= 0xfb00 as i32 && code <= 0xfb4f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsArabic(mut code: i32) -> i32 {
    return (code >= 0x600 as i32 && code <= 0x6ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsArabicPresentationFormsA(mut code: i32) -> i32 {
    return (code >= 0xfb50 as i32 && code <= 0xfdff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsArabicPresentationFormsB(mut code: i32) -> i32 {
    return (code >= 0xfe70 as i32 && code <= 0xfeff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsArmenian(mut code: i32) -> i32 {
    return (code >= 0x530 as i32 && code <= 0x58f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsArrows(mut code: i32) -> i32 {
    return (code >= 0x2190 as i32 && code <= 0x21ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsBasicLatin(mut code: i32) -> i32 {
    return (code >= 0 as i32 && code <= 0x7f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsBengali(mut code: i32) -> i32 {
    return (code >= 0x980 as i32 && code <= 0x9ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsBlockElements(mut code: i32) -> i32 {
    return (code >= 0x2580 as i32 && code <= 0x259f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsBopomofo(mut code: i32) -> i32 {
    return (code >= 0x3100 as i32 && code <= 0x312f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsBopomofoExtended(mut code: i32) -> i32 {
    return (code >= 0x31a0 as i32 && code <= 0x31bf as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsBoxDrawing(mut code: i32) -> i32 {
    return (code >= 0x2500 as i32 && code <= 0x257f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsBraillePatterns(mut code: i32) -> i32 {
    return (code >= 0x2800 as i32 && code <= 0x28ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsBuhid(mut code: i32) -> i32 {
    return (code >= 0x1740 as i32 && code <= 0x175f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsByzantineMusicalSymbols(mut code: i32) -> i32 {
    return (code >= 0x1d000 as i32 && code <= 0x1d0ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCJKCompatibility(mut code: i32) -> i32 {
    return (code >= 0x3300 as i32 && code <= 0x33ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCJKCompatibilityForms(mut code: i32) -> i32 {
    return (code >= 0xfe30 as i32 && code <= 0xfe4f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCJKCompatibilityIdeographs(mut code: i32) -> i32 {
    return (code >= 0xf900 as i32 && code <= 0xfaff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCJKCompatibilityIdeographsSupplement(mut code: i32) -> i32 {
    return (code >= 0x2f800 as i32 && code <= 0x2fa1f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCJKRadicalsSupplement(mut code: i32) -> i32 {
    return (code >= 0x2e80 as i32 && code <= 0x2eff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCJKSymbolsandPunctuation(mut code: i32) -> i32 {
    return (code >= 0x3000 as i32 && code <= 0x303f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCJKUnifiedIdeographs(mut code: i32) -> i32 {
    return (code >= 0x4e00 as i32 && code <= 0x9fff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCJKUnifiedIdeographsExtensionA(mut code: i32) -> i32 {
    return (code >= 0x3400 as i32 && code <= 0x4dbf as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCJKUnifiedIdeographsExtensionB(mut code: i32) -> i32 {
    return (code >= 0x20000 as i32 && code <= 0x2a6df as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCherokee(mut code: i32) -> i32 {
    return (code >= 0x13a0 as i32 && code <= 0x13ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCombiningDiacriticalMarks(mut code: i32) -> i32 {
    return (code >= 0x300 as i32 && code <= 0x36f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCombiningDiacriticalMarksforSymbols(mut code: i32) -> i32 {
    return (code >= 0x20d0 as i32 && code <= 0x20ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCombiningHalfMarks(mut code: i32) -> i32 {
    return (code >= 0xfe20 as i32 && code <= 0xfe2f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCombiningMarksforSymbols(mut code: i32) -> i32 {
    return (code >= 0x20d0 as i32 && code <= 0x20ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsControlPictures(mut code: i32) -> i32 {
    return (code >= 0x2400 as i32 && code <= 0x243f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCurrencySymbols(mut code: i32) -> i32 {
    return (code >= 0x20a0 as i32 && code <= 0x20cf as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCypriotSyllabary(mut code: i32) -> i32 {
    return (code >= 0x10800 as i32 && code <= 0x1083f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCyrillic(mut code: i32) -> i32 {
    return (code >= 0x400 as i32 && code <= 0x4ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCyrillicSupplement(mut code: i32) -> i32 {
    return (code >= 0x500 as i32 && code <= 0x52f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsDeseret(mut code: i32) -> i32 {
    return (code >= 0x10400 as i32 && code <= 0x1044f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsDevanagari(mut code: i32) -> i32 {
    return (code >= 0x900 as i32 && code <= 0x97f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsDingbats(mut code: i32) -> i32 {
    return (code >= 0x2700 as i32 && code <= 0x27bf as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsEnclosedAlphanumerics(mut code: i32) -> i32 {
    return (code >= 0x2460 as i32 && code <= 0x24ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsEnclosedCJKLettersandMonths(mut code: i32) -> i32 {
    return (code >= 0x3200 as i32 && code <= 0x32ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsEthiopic(mut code: i32) -> i32 {
    return (code >= 0x1200 as i32 && code <= 0x137f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsGeneralPunctuation(mut code: i32) -> i32 {
    return (code >= 0x2000 as i32 && code <= 0x206f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsGeometricShapes(mut code: i32) -> i32 {
    return (code >= 0x25a0 as i32 && code <= 0x25ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsGeorgian(mut code: i32) -> i32 {
    return (code >= 0x10a0 as i32 && code <= 0x10ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsGothic(mut code: i32) -> i32 {
    return (code >= 0x10330 as i32 && code <= 0x1034f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsGreek(mut code: i32) -> i32 {
    return (code >= 0x370 as i32 && code <= 0x3ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsGreekExtended(mut code: i32) -> i32 {
    return (code >= 0x1f00 as i32 && code <= 0x1fff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsGreekandCoptic(mut code: i32) -> i32 {
    return (code >= 0x370 as i32 && code <= 0x3ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsGujarati(mut code: i32) -> i32 {
    return (code >= 0xa80 as i32 && code <= 0xaff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsGurmukhi(mut code: i32) -> i32 {
    return (code >= 0xa00 as i32 && code <= 0xa7f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsHalfwidthandFullwidthForms(mut code: i32) -> i32 {
    return (code >= 0xff00 as i32 && code <= 0xffef as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsHangulCompatibilityJamo(mut code: i32) -> i32 {
    return (code >= 0x3130 as i32 && code <= 0x318f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsHangulJamo(mut code: i32) -> i32 {
    return (code >= 0x1100 as i32 && code <= 0x11ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsHangulSyllables(mut code: i32) -> i32 {
    return (code >= 0xac00 as i32 && code <= 0xd7af as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsHanunoo(mut code: i32) -> i32 {
    return (code >= 0x1720 as i32 && code <= 0x173f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsHebrew(mut code: i32) -> i32 {
    return (code >= 0x590 as i32 && code <= 0x5ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsHighPrivateUseSurrogates(mut code: i32) -> i32 {
    return (code >= 0xdb80 as i32 && code <= 0xdbff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsHighSurrogates(mut code: i32) -> i32 {
    return (code >= 0xd800 as i32 && code <= 0xdb7f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsHiragana(mut code: i32) -> i32 {
    return (code >= 0x3040 as i32 && code <= 0x309f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsIPAExtensions(mut code: i32) -> i32 {
    return (code >= 0x250 as i32 && code <= 0x2af as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsIdeographicDescriptionCharacters(mut code: i32) -> i32 {
    return (code >= 0x2ff0 as i32 && code <= 0x2fff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsKanbun(mut code: i32) -> i32 {
    return (code >= 0x3190 as i32 && code <= 0x319f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsKangxiRadicals(mut code: i32) -> i32 {
    return (code >= 0x2f00 as i32 && code <= 0x2fdf as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsKannada(mut code: i32) -> i32 {
    return (code >= 0xc80 as i32 && code <= 0xcff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsKatakana(mut code: i32) -> i32 {
    return (code >= 0x30a0 as i32 && code <= 0x30ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsKatakanaPhoneticExtensions(mut code: i32) -> i32 {
    return (code >= 0x31f0 as i32 && code <= 0x31ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsKhmer(mut code: i32) -> i32 {
    return (code >= 0x1780 as i32 && code <= 0x17ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsKhmerSymbols(mut code: i32) -> i32 {
    return (code >= 0x19e0 as i32 && code <= 0x19ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsLao(mut code: i32) -> i32 {
    return (code >= 0xe80 as i32 && code <= 0xeff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsLatin1Supplement(mut code: i32) -> i32 {
    return (code >= 0x80 as i32 && code <= 0xff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsLatinExtendedA(mut code: i32) -> i32 {
    return (code >= 0x100 as i32 && code <= 0x17f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsLatinExtendedB(mut code: i32) -> i32 {
    return (code >= 0x180 as i32 && code <= 0x24f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsLatinExtendedAdditional(mut code: i32) -> i32 {
    return (code >= 0x1e00 as i32 && code <= 0x1eff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsLetterlikeSymbols(mut code: i32) -> i32 {
    return (code >= 0x2100 as i32 && code <= 0x214f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsLimbu(mut code: i32) -> i32 {
    return (code >= 0x1900 as i32 && code <= 0x194f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsLinearBIdeograms(mut code: i32) -> i32 {
    return (code >= 0x10080 as i32 && code <= 0x100ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsLinearBSyllabary(mut code: i32) -> i32 {
    return (code >= 0x10000 as i32 && code <= 0x1007f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsLowSurrogates(mut code: i32) -> i32 {
    return (code >= 0xdc00 as i32 && code <= 0xdfff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMalayalam(mut code: i32) -> i32 {
    return (code >= 0xd00 as i32 && code <= 0xd7f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMathematicalAlphanumericSymbols(mut code: i32) -> i32 {
    return (code >= 0x1d400 as i32 && code <= 0x1d7ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMathematicalOperators(mut code: i32) -> i32 {
    return (code >= 0x2200 as i32 && code <= 0x22ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMiscellaneousMathematicalSymbolsA(mut code: i32) -> i32 {
    return (code >= 0x27c0 as i32 && code <= 0x27ef as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMiscellaneousMathematicalSymbolsB(mut code: i32) -> i32 {
    return (code >= 0x2980 as i32 && code <= 0x29ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMiscellaneousSymbols(mut code: i32) -> i32 {
    return (code >= 0x2600 as i32 && code <= 0x26ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMiscellaneousSymbolsandArrows(mut code: i32) -> i32 {
    return (code >= 0x2b00 as i32 && code <= 0x2bff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMiscellaneousTechnical(mut code: i32) -> i32 {
    return (code >= 0x2300 as i32 && code <= 0x23ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMongolian(mut code: i32) -> i32 {
    return (code >= 0x1800 as i32 && code <= 0x18af as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMusicalSymbols(mut code: i32) -> i32 {
    return (code >= 0x1d100 as i32 && code <= 0x1d1ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsMyanmar(mut code: i32) -> i32 {
    return (code >= 0x1000 as i32 && code <= 0x109f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsNumberForms(mut code: i32) -> i32 {
    return (code >= 0x2150 as i32 && code <= 0x218f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsOgham(mut code: i32) -> i32 {
    return (code >= 0x1680 as i32 && code <= 0x169f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsOldItalic(mut code: i32) -> i32 {
    return (code >= 0x10300 as i32 && code <= 0x1032f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsOpticalCharacterRecognition(mut code: i32) -> i32 {
    return (code >= 0x2440 as i32 && code <= 0x245f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsOriya(mut code: i32) -> i32 {
    return (code >= 0xb00 as i32 && code <= 0xb7f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsOsmanya(mut code: i32) -> i32 {
    return (code >= 0x10480 as i32 && code <= 0x104af as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsPhoneticExtensions(mut code: i32) -> i32 {
    return (code >= 0x1d00 as i32 && code <= 0x1d7f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsPrivateUse(mut code: i32) -> i32 {
    return (code >= 0xe000 as i32 && code <= 0xf8ff as i32
        || code >= 0xf0000 as i32 && code <= 0xfffff as i32
        || code >= 0x100000 as i32 && code <= 0x10ffff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsPrivateUseArea(mut code: i32) -> i32 {
    return (code >= 0xe000 as i32 && code <= 0xf8ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsRunic(mut code: i32) -> i32 {
    return (code >= 0x16a0 as i32 && code <= 0x16ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsShavian(mut code: i32) -> i32 {
    return (code >= 0x10450 as i32 && code <= 0x1047f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSinhala(mut code: i32) -> i32 {
    return (code >= 0xd80 as i32 && code <= 0xdff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSmallFormVariants(mut code: i32) -> i32 {
    return (code >= 0xfe50 as i32 && code <= 0xfe6f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSpacingModifierLetters(mut code: i32) -> i32 {
    return (code >= 0x2b0 as i32 && code <= 0x2ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSpecials(mut code: i32) -> i32 {
    return (code >= 0xfff0 as i32 && code <= 0xffff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSuperscriptsandSubscripts(mut code: i32) -> i32 {
    return (code >= 0x2070 as i32 && code <= 0x209f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSupplementalArrowsA(mut code: i32) -> i32 {
    return (code >= 0x27f0 as i32 && code <= 0x27ff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSupplementalArrowsB(mut code: i32) -> i32 {
    return (code >= 0x2900 as i32 && code <= 0x297f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSupplementalMathematicalOperators(mut code: i32) -> i32 {
    return (code >= 0x2a00 as i32 && code <= 0x2aff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSupplementaryPrivateUseAreaA(mut code: i32) -> i32 {
    return (code >= 0xf0000 as i32 && code <= 0xfffff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSupplementaryPrivateUseAreaB(mut code: i32) -> i32 {
    return (code >= 0x100000 as i32 && code <= 0x10ffff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsSyriac(mut code: i32) -> i32 {
    return (code >= 0x700 as i32 && code <= 0x74f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsTagalog(mut code: i32) -> i32 {
    return (code >= 0x1700 as i32 && code <= 0x171f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsTagbanwa(mut code: i32) -> i32 {
    return (code >= 0x1760 as i32 && code <= 0x177f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsTags(mut code: i32) -> i32 {
    return (code >= 0xe0000 as i32 && code <= 0xe007f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsTaiLe(mut code: i32) -> i32 {
    return (code >= 0x1950 as i32 && code <= 0x197f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsTaiXuanJingSymbols(mut code: i32) -> i32 {
    return (code >= 0x1d300 as i32 && code <= 0x1d35f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsTamil(mut code: i32) -> i32 {
    return (code >= 0xb80 as i32 && code <= 0xbff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsTelugu(mut code: i32) -> i32 {
    return (code >= 0xc00 as i32 && code <= 0xc7f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsThaana(mut code: i32) -> i32 {
    return (code >= 0x780 as i32 && code <= 0x7bf as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsThai(mut code: i32) -> i32 {
    return (code >= 0xe00 as i32 && code <= 0xe7f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsTibetan(mut code: i32) -> i32 {
    return (code >= 0xf00 as i32 && code <= 0xfff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsUgaritic(mut code: i32) -> i32 {
    return (code >= 0x10380 as i32 && code <= 0x1039f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsUnifiedCanadianAboriginalSyllabics(mut code: i32) -> i32 {
    return (code >= 0x1400 as i32 && code <= 0x167f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsVariationSelectors(mut code: i32) -> i32 {
    return (code >= 0xfe00 as i32 && code <= 0xfe0f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsVariationSelectorsSupplement(mut code: i32) -> i32 {
    return (code >= 0xe0100 as i32 && code <= 0xe01ef as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsYiRadicals(mut code: i32) -> i32 {
    return (code >= 0xa490 as i32 && code <= 0xa4cf as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsYiSyllables(mut code: i32) -> i32 {
    return (code >= 0xa000 as i32 && code <= 0xa48f as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsYijingHexagramSymbols(mut code: i32) -> i32 {
    return (code >= 0x4dc0 as i32 && code <= 0x4dff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsBlock(mut code: i32, mut block: *const i8) -> i32 {
    let mut func: Option<xmlIntFunc> = None;
    func = xmlUnicodeLookup(unsafe { &xmlUnicodeBlockTbl }, block);
    if func.is_none() {
        return -(1 as i32);
    }
    return unsafe { func.expect("non-null function pointer")(code) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatC(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlCG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatCc(mut code: i32) -> i32 {
    return (code >= 0 as i32 && code <= 0x1f as i32 || code >= 0x7f as i32 && code <= 0x9f as i32)
        as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatCf(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlCfG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatCo(mut code: i32) -> i32 {
    return (code == 0xe000 as i32
        || code == 0xf8ff as i32
        || code == 0xf0000 as i32
        || code == 0xffffd as i32
        || code == 0x100000 as i32
        || code == 0x10fffd as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatCs(mut code: i32) -> i32 {
    return (code == 0xd800 as i32
        || code >= 0xdb7f as i32 && code <= 0xdb80 as i32
        || code >= 0xdbff as i32 && code <= 0xdc00 as i32
        || code == 0xdfff as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatL(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlLG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatLl(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlLlG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatLm(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlLmG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatLo(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlLoG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatLt(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlLtG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatLu(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlLuG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatM(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlMG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatMc(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlMcG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatMe(mut code: i32) -> i32 {
    return (code >= 0x488 as i32 && code <= 0x489 as i32
        || code == 0x6de as i32
        || code >= 0x20dd as i32 && code <= 0x20e0 as i32
        || code >= 0x20e2 as i32 && code <= 0x20e4 as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatMn(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlMnG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatN(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlNG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatNd(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlNdG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatNl(mut code: i32) -> i32 {
    return (code >= 0x16ee as i32 && code <= 0x16f0 as i32
        || code >= 0x2160 as i32 && code <= 0x2183 as i32
        || code == 0x3007 as i32
        || code >= 0x3021 as i32 && code <= 0x3029 as i32
        || code >= 0x3038 as i32 && code <= 0x303a as i32
        || code == 0x1034a as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatNo(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlNoG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatP(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlPG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatPc(mut code: i32) -> i32 {
    return (code == 0x5f as i32
        || code >= 0x203f as i32 && code <= 0x2040 as i32
        || code == 0x2054 as i32
        || code == 0x30fb as i32
        || code >= 0xfe33 as i32 && code <= 0xfe34 as i32
        || code >= 0xfe4d as i32 && code <= 0xfe4f as i32
        || code == 0xff3f as i32
        || code == 0xff65 as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatPd(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlPdG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatPe(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlPeG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatPf(mut code: i32) -> i32 {
    return (code == 0xbb as i32
        || code == 0x2019 as i32
        || code == 0x201d as i32
        || code == 0x203a as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatPi(mut code: i32) -> i32 {
    return (code == 0xab as i32
        || code == 0x2018 as i32
        || code >= 0x201b as i32 && code <= 0x201c as i32
        || code == 0x201f as i32
        || code == 0x2039 as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatPo(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlPoG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatPs(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlPsG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatS(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlSG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatSc(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlScG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatSk(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlSkG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatSm(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlSmG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatSo(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlSoG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatZ(mut code: i32) -> i32 {
    return unsafe { xmlCharInRange(code as u32, &xmlZG) };
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatZl(mut code: i32) -> i32 {
    return (code == 0x2028 as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatZp(mut code: i32) -> i32 {
    return (code == 0x2029 as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCatZs(mut code: i32) -> i32 {
    return (code == 0x20 as i32
        || code == 0xa0 as i32
        || code == 0x1680 as i32
        || code == 0x180e as i32
        || code >= 0x2000 as i32 && code <= 0x200a as i32
        || code == 0x202f as i32
        || code == 0x205f as i32
        || code == 0x3000 as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUCSIsCat(mut code: i32, mut cat: *const i8) -> i32 {
    let mut func: Option<xmlIntFunc> = None;
    func = xmlUnicodeLookup(unsafe { &xmlUnicodeCatTbl }, cat);
    if func.is_none() {
        return -(1 as i32);
    }
    return unsafe { func.expect("non-null function pointer")(code) };
}
