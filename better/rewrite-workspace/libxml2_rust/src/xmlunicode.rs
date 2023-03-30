use ::libc;
extern "C" {
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    
}
pub use crate::src::chvalid::xmlCharInRange;
pub type xmlIntFunc = unsafe extern "C" fn(libc::c_int) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlUnicodeNameTable {
    pub table: *const xmlUnicodeRange,
    pub numentries: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlUnicodeRange {
    pub rangename: *const libc::c_char,
    pub func: Option::<xmlIntFunc>,
}
pub use crate::src::HTMLparser::xmlChRangeGroup;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChRangeGroup;
pub use crate::src::HTMLparser::xmlChLRange;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChLRange;
pub use crate::src::HTMLparser::xmlChSRange;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChSRange;
static mut xmlUnicodeBlocks: [xmlUnicodeRange; 128] = unsafe {
    [
        {
            let mut init = xmlUnicodeRange {
                rangename: b"AegeanNumbers\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsAegeanNumbers
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"AlphabeticPresentationForms\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsAlphabeticPresentationForms
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Arabic\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsArabic as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"ArabicPresentationForms-A\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsArabicPresentationFormsA
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"ArabicPresentationForms-B\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsArabicPresentationFormsB
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Armenian\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsArmenian as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Arrows\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsArrows as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"BasicLatin\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsBasicLatin
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Bengali\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsBengali as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"BlockElements\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsBlockElements
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Bopomofo\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsBopomofo as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"BopomofoExtended\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsBopomofoExtended
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"BoxDrawing\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsBoxDrawing
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"BraillePatterns\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsBraillePatterns
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Buhid\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsBuhid as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"ByzantineMusicalSymbols\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsByzantineMusicalSymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKCompatibility\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCJKCompatibility
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKCompatibilityForms\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsCJKCompatibilityForms
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKCompatibilityIdeographs\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsCJKCompatibilityIdeographs
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKCompatibilityIdeographsSupplement\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsCJKCompatibilityIdeographsSupplement
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKRadicalsSupplement\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsCJKRadicalsSupplement
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKSymbolsandPunctuation\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsCJKSymbolsandPunctuation
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKUnifiedIdeographs\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCJKUnifiedIdeographs
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKUnifiedIdeographsExtensionA\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsCJKUnifiedIdeographsExtensionA
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CJKUnifiedIdeographsExtensionB\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsCJKUnifiedIdeographsExtensionB
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Cherokee\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCherokee as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CombiningDiacriticalMarks\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsCombiningDiacriticalMarks
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CombiningDiacriticalMarksforSymbols\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsCombiningDiacriticalMarksforSymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CombiningHalfMarks\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCombiningHalfMarks
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CombiningMarksforSymbols\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsCombiningMarksforSymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"ControlPictures\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsControlPictures
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CurrencySymbols\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCurrencySymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CypriotSyllabary\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCypriotSyllabary
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Cyrillic\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCyrillic as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"CyrillicSupplement\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCyrillicSupplement
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Deseret\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsDeseret as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Devanagari\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsDevanagari
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Dingbats\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsDingbats as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"EnclosedAlphanumerics\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsEnclosedAlphanumerics
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"EnclosedCJKLettersandMonths\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsEnclosedCJKLettersandMonths
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Ethiopic\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsEthiopic as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"GeneralPunctuation\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsGeneralPunctuation
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"GeometricShapes\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsGeometricShapes
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Georgian\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsGeorgian as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Gothic\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsGothic as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Greek\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsGreek as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"GreekExtended\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsGreekExtended
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"GreekandCoptic\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsGreekandCoptic
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Gujarati\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsGujarati as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Gurmukhi\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsGurmukhi as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HalfwidthandFullwidthForms\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsHalfwidthandFullwidthForms
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HangulCompatibilityJamo\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsHangulCompatibilityJamo
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HangulJamo\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsHangulJamo
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HangulSyllables\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsHangulSyllables
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Hanunoo\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsHanunoo as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Hebrew\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsHebrew as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HighPrivateUseSurrogates\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsHighPrivateUseSurrogates
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"HighSurrogates\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsHighSurrogates
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Hiragana\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsHiragana as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"IPAExtensions\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsIPAExtensions
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"IdeographicDescriptionCharacters\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsIdeographicDescriptionCharacters
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Kanbun\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsKanbun as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"KangxiRadicals\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsKangxiRadicals
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Kannada\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsKannada as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Katakana\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsKatakana as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"KatakanaPhoneticExtensions\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsKatakanaPhoneticExtensions
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Khmer\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsKhmer as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"KhmerSymbols\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsKhmerSymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Lao\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsLao as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Latin-1Supplement\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsLatin1Supplement
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LatinExtended-A\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsLatinExtendedA
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LatinExtended-B\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsLatinExtendedB
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LatinExtendedAdditional\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsLatinExtendedAdditional
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LetterlikeSymbols\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsLetterlikeSymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Limbu\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsLimbu as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LinearBIdeograms\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsLinearBIdeograms
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LinearBSyllabary\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsLinearBSyllabary
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"LowSurrogates\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsLowSurrogates
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Malayalam\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsMalayalam as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MathematicalAlphanumericSymbols\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsMathematicalAlphanumericSymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MathematicalOperators\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsMathematicalOperators
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MiscellaneousMathematicalSymbols-A\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsMiscellaneousMathematicalSymbolsA
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MiscellaneousMathematicalSymbols-B\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsMiscellaneousMathematicalSymbolsB
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MiscellaneousSymbols\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsMiscellaneousSymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MiscellaneousSymbolsandArrows\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsMiscellaneousSymbolsandArrows
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MiscellaneousTechnical\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsMiscellaneousTechnical
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Mongolian\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsMongolian as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"MusicalSymbols\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsMusicalSymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Myanmar\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsMyanmar as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"NumberForms\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsNumberForms
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Ogham\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsOgham as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"OldItalic\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsOldItalic as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"OpticalCharacterRecognition\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsOpticalCharacterRecognition
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Oriya\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsOriya as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Osmanya\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsOsmanya as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"PhoneticExtensions\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsPhoneticExtensions
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"PrivateUse\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsPrivateUse
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"PrivateUseArea\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsPrivateUseArea
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Runic\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsRunic as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Shavian\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsShavian as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Sinhala\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsSinhala as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SmallFormVariants\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsSmallFormVariants
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SpacingModifierLetters\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsSpacingModifierLetters
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Specials\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsSpecials as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SuperscriptsandSubscripts\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsSuperscriptsandSubscripts
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SupplementalArrows-A\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsSupplementalArrowsA
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SupplementalArrows-B\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsSupplementalArrowsB
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SupplementalMathematicalOperators\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsSupplementalMathematicalOperators
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SupplementaryPrivateUseArea-A\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsSupplementaryPrivateUseAreaA
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"SupplementaryPrivateUseArea-B\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsSupplementaryPrivateUseAreaB
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Syriac\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsSyriac as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Tagalog\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsTagalog as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Tagbanwa\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsTagbanwa as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Tags\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsTags as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"TaiLe\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsTaiLe as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"TaiXuanJingSymbols\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsTaiXuanJingSymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Tamil\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsTamil as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Telugu\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsTelugu as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Thaana\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsThaana as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Thai\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsThai as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Tibetan\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsTibetan as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Ugaritic\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsUgaritic as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"UnifiedCanadianAboriginalSyllabics\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsUnifiedCanadianAboriginalSyllabics
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"VariationSelectors\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsVariationSelectors
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"VariationSelectorsSupplement\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsVariationSelectorsSupplement
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"YiRadicals\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsYiRadicals
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"YiSyllables\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsYiSyllables
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"YijingHexagramSymbols\0" as *const u8
                    as *const libc::c_char,
                func: Some(
                    xmlUCSIsYijingHexagramSymbols
                        as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
    ]
};
static mut xmlUnicodeCats: [xmlUnicodeRange; 36] = unsafe {
    [
        {
            let mut init = xmlUnicodeRange {
                rangename: b"C\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatC as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Cc\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatCc as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Cf\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatCf as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Co\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatCo as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Cs\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatCs as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"L\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatL as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Ll\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatLl as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Lm\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatLm as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Lo\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatLo as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Lt\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatLt as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Lu\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatLu as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"M\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatM as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Mc\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatMc as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Me\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatMe as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Mn\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatMn as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"N\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatN as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Nd\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatNd as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Nl\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatNl as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"No\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatNo as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"P\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatP as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Pc\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatPc as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Pd\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatPd as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Pe\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatPe as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Pf\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatPf as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Pi\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatPi as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Po\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatPo as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Ps\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatPs as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"S\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatS as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Sc\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatSc as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Sk\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatSk as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Sm\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatSm as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"So\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatSo as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Z\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatZ as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Zl\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatZl as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Zp\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatZp as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = xmlUnicodeRange {
                rangename: b"Zs\0" as *const u8 as *const libc::c_char,
                func: Some(
                    xmlUCSIsCatZs as unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                ),
            };
            init
        },
    ]
};
static mut xmlCS: [xmlChSRange; 18] = [
    {
        let mut init = _xmlChSRange {
            low: 0 as libc::c_int as libc::c_ushort,
            high: 0x1f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7f as libc::c_int as libc::c_ushort,
            high: 0x9f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xad as libc::c_int as libc::c_ushort,
            high: 0xad as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x600 as libc::c_int as libc::c_ushort,
            high: 0x603 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6dd as libc::c_int as libc::c_ushort,
            high: 0x6dd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x70f as libc::c_int as libc::c_ushort,
            high: 0x70f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b4 as libc::c_int as libc::c_ushort,
            high: 0x17b5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x200b as libc::c_int as libc::c_ushort,
            high: 0x200f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x202a as libc::c_int as libc::c_ushort,
            high: 0x202e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2060 as libc::c_int as libc::c_ushort,
            high: 0x2063 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x206a as libc::c_int as libc::c_ushort,
            high: 0x206f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd800 as libc::c_int as libc::c_ushort,
            high: 0xd800 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdb7f as libc::c_int as libc::c_ushort,
            high: 0xdb80 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdbff as libc::c_int as libc::c_ushort,
            high: 0xdc00 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdfff as libc::c_int as libc::c_ushort,
            high: 0xe000 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf8ff as libc::c_int as libc::c_ushort,
            high: 0xf8ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfeff as libc::c_int as libc::c_ushort,
            high: 0xfeff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfff9 as libc::c_int as libc::c_ushort,
            high: 0xfffb as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlCL: [xmlChLRange; 7] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d173 as libc::c_int as libc::c_uint,
            high: 0x1d17a as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0001 as libc::c_int as libc::c_uint,
            high: 0xe0001 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0020 as libc::c_int as libc::c_uint,
            high: 0xe007f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xf0000 as libc::c_int as libc::c_uint,
            high: 0xf0000 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xffffd as libc::c_int as libc::c_uint,
            high: 0xffffd as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x100000 as libc::c_int as libc::c_uint,
            high: 0x100000 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10fffd as libc::c_int as libc::c_uint,
            high: 0x10fffd as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlCG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 18 as libc::c_int,
            nbLongRange: 7 as libc::c_int,
            shortRange: xmlCS.as_ptr(),
            longRange: xmlCL.as_ptr(),
        };
        init
    }
};
static mut xmlCfS: [xmlChSRange; 11] = [
    {
        let mut init = _xmlChSRange {
            low: 0xad as libc::c_int as libc::c_ushort,
            high: 0xad as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x600 as libc::c_int as libc::c_ushort,
            high: 0x603 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6dd as libc::c_int as libc::c_ushort,
            high: 0x6dd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x70f as libc::c_int as libc::c_ushort,
            high: 0x70f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b4 as libc::c_int as libc::c_ushort,
            high: 0x17b5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x200b as libc::c_int as libc::c_ushort,
            high: 0x200f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x202a as libc::c_int as libc::c_ushort,
            high: 0x202e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2060 as libc::c_int as libc::c_ushort,
            high: 0x2063 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x206a as libc::c_int as libc::c_ushort,
            high: 0x206f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfeff as libc::c_int as libc::c_ushort,
            high: 0xfeff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfff9 as libc::c_int as libc::c_ushort,
            high: 0xfffb as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlCfL: [xmlChLRange; 3] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d173 as libc::c_int as libc::c_uint,
            high: 0x1d17a as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0001 as libc::c_int as libc::c_uint,
            high: 0xe0001 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0020 as libc::c_int as libc::c_uint,
            high: 0xe007f as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlCfG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 11 as libc::c_int,
            nbLongRange: 3 as libc::c_int,
            shortRange: xmlCfS.as_ptr(),
            longRange: xmlCfL.as_ptr(),
        };
        init
    }
};
static mut xmlLS: [xmlChSRange; 279] = [
    {
        let mut init = _xmlChSRange {
            low: 0x41 as libc::c_int as libc::c_ushort,
            high: 0x5a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x61 as libc::c_int as libc::c_ushort,
            high: 0x7a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaa as libc::c_int as libc::c_ushort,
            high: 0xaa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5 as libc::c_int as libc::c_ushort,
            high: 0xb5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba as libc::c_int as libc::c_ushort,
            high: 0xba as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc0 as libc::c_int as libc::c_ushort,
            high: 0xd6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd8 as libc::c_int as libc::c_ushort,
            high: 0xf6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf8 as libc::c_int as libc::c_ushort,
            high: 0x236 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x250 as libc::c_int as libc::c_ushort,
            high: 0x2c1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c6 as libc::c_int as libc::c_ushort,
            high: 0x2d1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e0 as libc::c_int as libc::c_ushort,
            high: 0x2e4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ee as libc::c_int as libc::c_ushort,
            high: 0x2ee as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x37a as libc::c_int as libc::c_ushort,
            high: 0x37a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x386 as libc::c_int as libc::c_ushort,
            high: 0x386 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x388 as libc::c_int as libc::c_ushort,
            high: 0x38a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x38c as libc::c_int as libc::c_ushort,
            high: 0x38c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x38e as libc::c_int as libc::c_ushort,
            high: 0x3a1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3a3 as libc::c_int as libc::c_ushort,
            high: 0x3ce as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d0 as libc::c_int as libc::c_ushort,
            high: 0x3f5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f7 as libc::c_int as libc::c_ushort,
            high: 0x3fb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x400 as libc::c_int as libc::c_ushort,
            high: 0x481 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48a as libc::c_int as libc::c_ushort,
            high: 0x4ce as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d0 as libc::c_int as libc::c_ushort,
            high: 0x4f5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f8 as libc::c_int as libc::c_ushort,
            high: 0x4f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x500 as libc::c_int as libc::c_ushort,
            high: 0x50f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x531 as libc::c_int as libc::c_ushort,
            high: 0x556 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x559 as libc::c_int as libc::c_ushort,
            high: 0x559 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x561 as libc::c_int as libc::c_ushort,
            high: 0x587 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5d0 as libc::c_int as libc::c_ushort,
            high: 0x5ea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5f0 as libc::c_int as libc::c_ushort,
            high: 0x5f2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x621 as libc::c_int as libc::c_ushort,
            high: 0x63a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x640 as libc::c_int as libc::c_ushort,
            high: 0x64a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x66e as libc::c_int as libc::c_ushort,
            high: 0x66f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x671 as libc::c_int as libc::c_ushort,
            high: 0x6d3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d5 as libc::c_int as libc::c_ushort,
            high: 0x6d5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e5 as libc::c_int as libc::c_ushort,
            high: 0x6e6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ee as libc::c_int as libc::c_ushort,
            high: 0x6ef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6fa as libc::c_int as libc::c_ushort,
            high: 0x6fc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ff as libc::c_int as libc::c_ushort,
            high: 0x6ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x710 as libc::c_int as libc::c_ushort,
            high: 0x710 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x712 as libc::c_int as libc::c_ushort,
            high: 0x72f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x74d as libc::c_int as libc::c_ushort,
            high: 0x74f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x780 as libc::c_int as libc::c_ushort,
            high: 0x7a5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7b1 as libc::c_int as libc::c_ushort,
            high: 0x7b1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x904 as libc::c_int as libc::c_ushort,
            high: 0x939 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93d as libc::c_int as libc::c_ushort,
            high: 0x93d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x950 as libc::c_int as libc::c_ushort,
            high: 0x950 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x958 as libc::c_int as libc::c_ushort,
            high: 0x961 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x985 as libc::c_int as libc::c_ushort,
            high: 0x98c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x98f as libc::c_int as libc::c_ushort,
            high: 0x990 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x993 as libc::c_int as libc::c_ushort,
            high: 0x9a8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9aa as libc::c_int as libc::c_ushort,
            high: 0x9b0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9b2 as libc::c_int as libc::c_ushort,
            high: 0x9b2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9b6 as libc::c_int as libc::c_ushort,
            high: 0x9b9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9bd as libc::c_int as libc::c_ushort,
            high: 0x9bd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9dc as libc::c_int as libc::c_ushort,
            high: 0x9dd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9df as libc::c_int as libc::c_ushort,
            high: 0x9e1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f0 as libc::c_int as libc::c_ushort,
            high: 0x9f1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa05 as libc::c_int as libc::c_ushort,
            high: 0xa0a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa0f as libc::c_int as libc::c_ushort,
            high: 0xa10 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa13 as libc::c_int as libc::c_ushort,
            high: 0xa28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa2a as libc::c_int as libc::c_ushort,
            high: 0xa30 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa32 as libc::c_int as libc::c_ushort,
            high: 0xa33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa35 as libc::c_int as libc::c_ushort,
            high: 0xa36 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa38 as libc::c_int as libc::c_ushort,
            high: 0xa39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa59 as libc::c_int as libc::c_ushort,
            high: 0xa5c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa5e as libc::c_int as libc::c_ushort,
            high: 0xa5e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa72 as libc::c_int as libc::c_ushort,
            high: 0xa74 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa85 as libc::c_int as libc::c_ushort,
            high: 0xa8d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa8f as libc::c_int as libc::c_ushort,
            high: 0xa91 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa93 as libc::c_int as libc::c_ushort,
            high: 0xaa8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaaa as libc::c_int as libc::c_ushort,
            high: 0xab0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xab2 as libc::c_int as libc::c_ushort,
            high: 0xab3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xab5 as libc::c_int as libc::c_ushort,
            high: 0xab9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabd as libc::c_int as libc::c_ushort,
            high: 0xabd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xad0 as libc::c_int as libc::c_ushort,
            high: 0xad0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae0 as libc::c_int as libc::c_ushort,
            high: 0xae1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb05 as libc::c_int as libc::c_ushort,
            high: 0xb0c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb0f as libc::c_int as libc::c_ushort,
            high: 0xb10 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb13 as libc::c_int as libc::c_ushort,
            high: 0xb28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb2a as libc::c_int as libc::c_ushort,
            high: 0xb30 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb32 as libc::c_int as libc::c_ushort,
            high: 0xb33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb35 as libc::c_int as libc::c_ushort,
            high: 0xb39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3d as libc::c_int as libc::c_ushort,
            high: 0xb3d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5c as libc::c_int as libc::c_ushort,
            high: 0xb5d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5f as libc::c_int as libc::c_ushort,
            high: 0xb61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb71 as libc::c_int as libc::c_ushort,
            high: 0xb71 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb83 as libc::c_int as libc::c_ushort,
            high: 0xb83 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb85 as libc::c_int as libc::c_ushort,
            high: 0xb8a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb8e as libc::c_int as libc::c_ushort,
            high: 0xb90 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb92 as libc::c_int as libc::c_ushort,
            high: 0xb95 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb99 as libc::c_int as libc::c_ushort,
            high: 0xb9a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9c as libc::c_int as libc::c_ushort,
            high: 0xb9c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9e as libc::c_int as libc::c_ushort,
            high: 0xb9f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba3 as libc::c_int as libc::c_ushort,
            high: 0xba4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba8 as libc::c_int as libc::c_ushort,
            high: 0xbaa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbae as libc::c_int as libc::c_ushort,
            high: 0xbb5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbb7 as libc::c_int as libc::c_ushort,
            high: 0xbb9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc05 as libc::c_int as libc::c_ushort,
            high: 0xc0c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc0e as libc::c_int as libc::c_ushort,
            high: 0xc10 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc12 as libc::c_int as libc::c_ushort,
            high: 0xc28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc2a as libc::c_int as libc::c_ushort,
            high: 0xc33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc35 as libc::c_int as libc::c_ushort,
            high: 0xc39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc60 as libc::c_int as libc::c_ushort,
            high: 0xc61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc85 as libc::c_int as libc::c_ushort,
            high: 0xc8c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc8e as libc::c_int as libc::c_ushort,
            high: 0xc90 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc92 as libc::c_int as libc::c_ushort,
            high: 0xca8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcaa as libc::c_int as libc::c_ushort,
            high: 0xcb3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcb5 as libc::c_int as libc::c_ushort,
            high: 0xcb9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbd as libc::c_int as libc::c_ushort,
            high: 0xcbd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcde as libc::c_int as libc::c_ushort,
            high: 0xcde as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xce0 as libc::c_int as libc::c_ushort,
            high: 0xce1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd05 as libc::c_int as libc::c_ushort,
            high: 0xd0c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd0e as libc::c_int as libc::c_ushort,
            high: 0xd10 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd12 as libc::c_int as libc::c_ushort,
            high: 0xd28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd2a as libc::c_int as libc::c_ushort,
            high: 0xd39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd60 as libc::c_int as libc::c_ushort,
            high: 0xd61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd85 as libc::c_int as libc::c_ushort,
            high: 0xd96 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd9a as libc::c_int as libc::c_ushort,
            high: 0xdb1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdb3 as libc::c_int as libc::c_ushort,
            high: 0xdbb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdbd as libc::c_int as libc::c_ushort,
            high: 0xdbd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdc0 as libc::c_int as libc::c_ushort,
            high: 0xdc6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe01 as libc::c_int as libc::c_ushort,
            high: 0xe30 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe32 as libc::c_int as libc::c_ushort,
            high: 0xe33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe40 as libc::c_int as libc::c_ushort,
            high: 0xe46 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe81 as libc::c_int as libc::c_ushort,
            high: 0xe82 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe84 as libc::c_int as libc::c_ushort,
            high: 0xe84 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe87 as libc::c_int as libc::c_ushort,
            high: 0xe88 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe8a as libc::c_int as libc::c_ushort,
            high: 0xe8a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe8d as libc::c_int as libc::c_ushort,
            high: 0xe8d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe94 as libc::c_int as libc::c_ushort,
            high: 0xe97 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe99 as libc::c_int as libc::c_ushort,
            high: 0xe9f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea1 as libc::c_int as libc::c_ushort,
            high: 0xea3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea5 as libc::c_int as libc::c_ushort,
            high: 0xea5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea7 as libc::c_int as libc::c_ushort,
            high: 0xea7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeaa as libc::c_int as libc::c_ushort,
            high: 0xeab as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xead as libc::c_int as libc::c_ushort,
            high: 0xeb0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb2 as libc::c_int as libc::c_ushort,
            high: 0xeb3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xebd as libc::c_int as libc::c_ushort,
            high: 0xebd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec0 as libc::c_int as libc::c_ushort,
            high: 0xec4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec6 as libc::c_int as libc::c_ushort,
            high: 0xec6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xedc as libc::c_int as libc::c_ushort,
            high: 0xedd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf00 as libc::c_int as libc::c_ushort,
            high: 0xf00 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf40 as libc::c_int as libc::c_ushort,
            high: 0xf47 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf49 as libc::c_int as libc::c_ushort,
            high: 0xf6a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf88 as libc::c_int as libc::c_ushort,
            high: 0xf8b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1000 as libc::c_int as libc::c_ushort,
            high: 0x1021 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1023 as libc::c_int as libc::c_ushort,
            high: 0x1027 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1029 as libc::c_int as libc::c_ushort,
            high: 0x102a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1050 as libc::c_int as libc::c_ushort,
            high: 0x1055 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10a0 as libc::c_int as libc::c_ushort,
            high: 0x10c5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10d0 as libc::c_int as libc::c_ushort,
            high: 0x10f8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1100 as libc::c_int as libc::c_ushort,
            high: 0x1159 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x115f as libc::c_int as libc::c_ushort,
            high: 0x11a2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11a8 as libc::c_int as libc::c_ushort,
            high: 0x11f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1200 as libc::c_int as libc::c_ushort,
            high: 0x1206 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1208 as libc::c_int as libc::c_ushort,
            high: 0x1246 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1248 as libc::c_int as libc::c_ushort,
            high: 0x1248 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x124a as libc::c_int as libc::c_ushort,
            high: 0x124d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1250 as libc::c_int as libc::c_ushort,
            high: 0x1256 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1258 as libc::c_int as libc::c_ushort,
            high: 0x1258 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x125a as libc::c_int as libc::c_ushort,
            high: 0x125d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1260 as libc::c_int as libc::c_ushort,
            high: 0x1286 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1288 as libc::c_int as libc::c_ushort,
            high: 0x1288 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x128a as libc::c_int as libc::c_ushort,
            high: 0x128d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1290 as libc::c_int as libc::c_ushort,
            high: 0x12ae as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b0 as libc::c_int as libc::c_ushort,
            high: 0x12b0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b2 as libc::c_int as libc::c_ushort,
            high: 0x12b5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b8 as libc::c_int as libc::c_ushort,
            high: 0x12be as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c0 as libc::c_int as libc::c_ushort,
            high: 0x12c0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c2 as libc::c_int as libc::c_ushort,
            high: 0x12c5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c8 as libc::c_int as libc::c_ushort,
            high: 0x12ce as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12d0 as libc::c_int as libc::c_ushort,
            high: 0x12d6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12d8 as libc::c_int as libc::c_ushort,
            high: 0x12ee as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12f0 as libc::c_int as libc::c_ushort,
            high: 0x130e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1310 as libc::c_int as libc::c_ushort,
            high: 0x1310 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1312 as libc::c_int as libc::c_ushort,
            high: 0x1315 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1318 as libc::c_int as libc::c_ushort,
            high: 0x131e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1320 as libc::c_int as libc::c_ushort,
            high: 0x1346 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1348 as libc::c_int as libc::c_ushort,
            high: 0x135a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13a0 as libc::c_int as libc::c_ushort,
            high: 0x13f4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1401 as libc::c_int as libc::c_ushort,
            high: 0x166c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x166f as libc::c_int as libc::c_ushort,
            high: 0x1676 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1681 as libc::c_int as libc::c_ushort,
            high: 0x169a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16a0 as libc::c_int as libc::c_ushort,
            high: 0x16ea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1700 as libc::c_int as libc::c_ushort,
            high: 0x170c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x170e as libc::c_int as libc::c_ushort,
            high: 0x1711 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1720 as libc::c_int as libc::c_ushort,
            high: 0x1731 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1740 as libc::c_int as libc::c_ushort,
            high: 0x1751 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1760 as libc::c_int as libc::c_ushort,
            high: 0x176c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x176e as libc::c_int as libc::c_ushort,
            high: 0x1770 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1780 as libc::c_int as libc::c_ushort,
            high: 0x17b3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d7 as libc::c_int as libc::c_ushort,
            high: 0x17d7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17dc as libc::c_int as libc::c_ushort,
            high: 0x17dc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1820 as libc::c_int as libc::c_ushort,
            high: 0x1877 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1880 as libc::c_int as libc::c_ushort,
            high: 0x18a8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1900 as libc::c_int as libc::c_ushort,
            high: 0x191c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1950 as libc::c_int as libc::c_ushort,
            high: 0x196d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1970 as libc::c_int as libc::c_ushort,
            high: 0x1974 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d00 as libc::c_int as libc::c_ushort,
            high: 0x1d6b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e00 as libc::c_int as libc::c_ushort,
            high: 0x1e9b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea0 as libc::c_int as libc::c_ushort,
            high: 0x1ef9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f00 as libc::c_int as libc::c_ushort,
            high: 0x1f15 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f18 as libc::c_int as libc::c_ushort,
            high: 0x1f1d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f20 as libc::c_int as libc::c_ushort,
            high: 0x1f45 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f48 as libc::c_int as libc::c_ushort,
            high: 0x1f4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f50 as libc::c_int as libc::c_ushort,
            high: 0x1f57 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f59 as libc::c_int as libc::c_ushort,
            high: 0x1f59 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5b as libc::c_int as libc::c_ushort,
            high: 0x1f5b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5d as libc::c_int as libc::c_ushort,
            high: 0x1f5d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5f as libc::c_int as libc::c_ushort,
            high: 0x1f7d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f80 as libc::c_int as libc::c_ushort,
            high: 0x1fb4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fb6 as libc::c_int as libc::c_ushort,
            high: 0x1fbc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbe as libc::c_int as libc::c_ushort,
            high: 0x1fbe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc2 as libc::c_int as libc::c_ushort,
            high: 0x1fc4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc6 as libc::c_int as libc::c_ushort,
            high: 0x1fcc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd0 as libc::c_int as libc::c_ushort,
            high: 0x1fd3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd6 as libc::c_int as libc::c_ushort,
            high: 0x1fdb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fe0 as libc::c_int as libc::c_ushort,
            high: 0x1fec as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff2 as libc::c_int as libc::c_ushort,
            high: 0x1ff4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff6 as libc::c_int as libc::c_ushort,
            high: 0x1ffc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2071 as libc::c_int as libc::c_ushort,
            high: 0x2071 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207f as libc::c_int as libc::c_ushort,
            high: 0x207f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2102 as libc::c_int as libc::c_ushort,
            high: 0x2102 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2107 as libc::c_int as libc::c_ushort,
            high: 0x2107 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x210a as libc::c_int as libc::c_ushort,
            high: 0x2113 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2115 as libc::c_int as libc::c_ushort,
            high: 0x2115 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2119 as libc::c_int as libc::c_ushort,
            high: 0x211d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2124 as libc::c_int as libc::c_ushort,
            high: 0x2124 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2126 as libc::c_int as libc::c_ushort,
            high: 0x2126 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2128 as libc::c_int as libc::c_ushort,
            high: 0x2128 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212a as libc::c_int as libc::c_ushort,
            high: 0x212d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212f as libc::c_int as libc::c_ushort,
            high: 0x2131 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2133 as libc::c_int as libc::c_ushort,
            high: 0x2139 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213d as libc::c_int as libc::c_ushort,
            high: 0x213f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2145 as libc::c_int as libc::c_ushort,
            high: 0x2149 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3005 as libc::c_int as libc::c_ushort,
            high: 0x3006 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3031 as libc::c_int as libc::c_ushort,
            high: 0x3035 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303b as libc::c_int as libc::c_ushort,
            high: 0x303c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3041 as libc::c_int as libc::c_ushort,
            high: 0x3096 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309d as libc::c_int as libc::c_ushort,
            high: 0x309f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30a1 as libc::c_int as libc::c_ushort,
            high: 0x30fa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30fc as libc::c_int as libc::c_ushort,
            high: 0x30ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3105 as libc::c_int as libc::c_ushort,
            high: 0x312c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3131 as libc::c_int as libc::c_ushort,
            high: 0x318e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x31a0 as libc::c_int as libc::c_ushort,
            high: 0x31b7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x31f0 as libc::c_int as libc::c_ushort,
            high: 0x31ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3400 as libc::c_int as libc::c_ushort,
            high: 0x3400 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4db5 as libc::c_int as libc::c_ushort,
            high: 0x4db5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e00 as libc::c_int as libc::c_ushort,
            high: 0x4e00 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9fa5 as libc::c_int as libc::c_ushort,
            high: 0x9fa5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa000 as libc::c_int as libc::c_ushort,
            high: 0xa48c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac00 as libc::c_int as libc::c_ushort,
            high: 0xac00 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd7a3 as libc::c_int as libc::c_ushort,
            high: 0xd7a3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf900 as libc::c_int as libc::c_ushort,
            high: 0xfa2d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfa30 as libc::c_int as libc::c_ushort,
            high: 0xfa6a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb00 as libc::c_int as libc::c_ushort,
            high: 0xfb06 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb13 as libc::c_int as libc::c_ushort,
            high: 0xfb17 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1d as libc::c_int as libc::c_ushort,
            high: 0xfb1d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1f as libc::c_int as libc::c_ushort,
            high: 0xfb28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb2a as libc::c_int as libc::c_ushort,
            high: 0xfb36 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb38 as libc::c_int as libc::c_ushort,
            high: 0xfb3c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb3e as libc::c_int as libc::c_ushort,
            high: 0xfb3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb40 as libc::c_int as libc::c_ushort,
            high: 0xfb41 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb43 as libc::c_int as libc::c_ushort,
            high: 0xfb44 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb46 as libc::c_int as libc::c_ushort,
            high: 0xfbb1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfbd3 as libc::c_int as libc::c_ushort,
            high: 0xfd3d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd50 as libc::c_int as libc::c_ushort,
            high: 0xfd8f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd92 as libc::c_int as libc::c_ushort,
            high: 0xfdc7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfdf0 as libc::c_int as libc::c_ushort,
            high: 0xfdfb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe70 as libc::c_int as libc::c_ushort,
            high: 0xfe74 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe76 as libc::c_int as libc::c_ushort,
            high: 0xfefc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff21 as libc::c_int as libc::c_ushort,
            high: 0xff3a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff41 as libc::c_int as libc::c_ushort,
            high: 0xff5a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff66 as libc::c_int as libc::c_ushort,
            high: 0xffbe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffc2 as libc::c_int as libc::c_ushort,
            high: 0xffc7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffca as libc::c_int as libc::c_ushort,
            high: 0xffcf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffd2 as libc::c_int as libc::c_ushort,
            high: 0xffd7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffda as libc::c_int as libc::c_ushort,
            high: 0xffdc as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlLL: [xmlChLRange; 50] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10000 as libc::c_int as libc::c_uint,
            high: 0x1000b as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1000d as libc::c_int as libc::c_uint,
            high: 0x10026 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10028 as libc::c_int as libc::c_uint,
            high: 0x1003a as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1003c as libc::c_int as libc::c_uint,
            high: 0x1003d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1003f as libc::c_int as libc::c_uint,
            high: 0x1004d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10050 as libc::c_int as libc::c_uint,
            high: 0x1005d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10080 as libc::c_int as libc::c_uint,
            high: 0x100fa as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10300 as libc::c_int as libc::c_uint,
            high: 0x1031e as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10330 as libc::c_int as libc::c_uint,
            high: 0x10349 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10380 as libc::c_int as libc::c_uint,
            high: 0x1039d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10400 as libc::c_int as libc::c_uint,
            high: 0x1049d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10800 as libc::c_int as libc::c_uint,
            high: 0x10805 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10808 as libc::c_int as libc::c_uint,
            high: 0x10808 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1080a as libc::c_int as libc::c_uint,
            high: 0x10835 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10837 as libc::c_int as libc::c_uint,
            high: 0x10838 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1083c as libc::c_int as libc::c_uint,
            high: 0x1083c as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1083f as libc::c_int as libc::c_uint,
            high: 0x1083f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d400 as libc::c_int as libc::c_uint,
            high: 0x1d454 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d456 as libc::c_int as libc::c_uint,
            high: 0x1d49c as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d49e as libc::c_int as libc::c_uint,
            high: 0x1d49f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a2 as libc::c_int as libc::c_uint,
            high: 0x1d4a2 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a5 as libc::c_int as libc::c_uint,
            high: 0x1d4a6 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a9 as libc::c_int as libc::c_uint,
            high: 0x1d4ac as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4ae as libc::c_int as libc::c_uint,
            high: 0x1d4b9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4bb as libc::c_int as libc::c_uint,
            high: 0x1d4bb as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4bd as libc::c_int as libc::c_uint,
            high: 0x1d4c3 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4c5 as libc::c_int as libc::c_uint,
            high: 0x1d505 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d507 as libc::c_int as libc::c_uint,
            high: 0x1d50a as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d50d as libc::c_int as libc::c_uint,
            high: 0x1d514 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d516 as libc::c_int as libc::c_uint,
            high: 0x1d51c as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d51e as libc::c_int as libc::c_uint,
            high: 0x1d539 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d53b as libc::c_int as libc::c_uint,
            high: 0x1d53e as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d540 as libc::c_int as libc::c_uint,
            high: 0x1d544 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d546 as libc::c_int as libc::c_uint,
            high: 0x1d546 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d54a as libc::c_int as libc::c_uint,
            high: 0x1d550 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d552 as libc::c_int as libc::c_uint,
            high: 0x1d6a3 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6a8 as libc::c_int as libc::c_uint,
            high: 0x1d6c0 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6c2 as libc::c_int as libc::c_uint,
            high: 0x1d6da as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6dc as libc::c_int as libc::c_uint,
            high: 0x1d6fa as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6fc as libc::c_int as libc::c_uint,
            high: 0x1d714 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d716 as libc::c_int as libc::c_uint,
            high: 0x1d734 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d736 as libc::c_int as libc::c_uint,
            high: 0x1d74e as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d750 as libc::c_int as libc::c_uint,
            high: 0x1d76e as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d770 as libc::c_int as libc::c_uint,
            high: 0x1d788 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d78a as libc::c_int as libc::c_uint,
            high: 0x1d7a8 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7aa as libc::c_int as libc::c_uint,
            high: 0x1d7c2 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7c4 as libc::c_int as libc::c_uint,
            high: 0x1d7c9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x20000 as libc::c_int as libc::c_uint,
            high: 0x20000 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x2a6d6 as libc::c_int as libc::c_uint,
            high: 0x2a6d6 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x2f800 as libc::c_int as libc::c_uint,
            high: 0x2fa1d as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlLG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 279 as libc::c_int,
            nbLongRange: 50 as libc::c_int,
            shortRange: xmlLS.as_ptr(),
            longRange: xmlLL.as_ptr(),
        };
        init
    }
};
static mut xmlLlS: [xmlChSRange; 396] = [
    {
        let mut init = _xmlChSRange {
            low: 0x61 as libc::c_int as libc::c_ushort,
            high: 0x7a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaa as libc::c_int as libc::c_ushort,
            high: 0xaa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5 as libc::c_int as libc::c_ushort,
            high: 0xb5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba as libc::c_int as libc::c_ushort,
            high: 0xba as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdf as libc::c_int as libc::c_ushort,
            high: 0xf6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf8 as libc::c_int as libc::c_ushort,
            high: 0xff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x101 as libc::c_int as libc::c_ushort,
            high: 0x101 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x103 as libc::c_int as libc::c_ushort,
            high: 0x103 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x105 as libc::c_int as libc::c_ushort,
            high: 0x105 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x107 as libc::c_int as libc::c_ushort,
            high: 0x107 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x109 as libc::c_int as libc::c_ushort,
            high: 0x109 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10b as libc::c_int as libc::c_ushort,
            high: 0x10b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10d as libc::c_int as libc::c_ushort,
            high: 0x10d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10f as libc::c_int as libc::c_ushort,
            high: 0x10f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x111 as libc::c_int as libc::c_ushort,
            high: 0x111 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x113 as libc::c_int as libc::c_ushort,
            high: 0x113 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x115 as libc::c_int as libc::c_ushort,
            high: 0x115 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x117 as libc::c_int as libc::c_ushort,
            high: 0x117 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x119 as libc::c_int as libc::c_ushort,
            high: 0x119 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11b as libc::c_int as libc::c_ushort,
            high: 0x11b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11d as libc::c_int as libc::c_ushort,
            high: 0x11d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11f as libc::c_int as libc::c_ushort,
            high: 0x11f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x121 as libc::c_int as libc::c_ushort,
            high: 0x121 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x123 as libc::c_int as libc::c_ushort,
            high: 0x123 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x125 as libc::c_int as libc::c_ushort,
            high: 0x125 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x127 as libc::c_int as libc::c_ushort,
            high: 0x127 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x129 as libc::c_int as libc::c_ushort,
            high: 0x129 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b as libc::c_int as libc::c_ushort,
            high: 0x12b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12d as libc::c_int as libc::c_ushort,
            high: 0x12d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12f as libc::c_int as libc::c_ushort,
            high: 0x12f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x131 as libc::c_int as libc::c_ushort,
            high: 0x131 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x133 as libc::c_int as libc::c_ushort,
            high: 0x133 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x135 as libc::c_int as libc::c_ushort,
            high: 0x135 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x137 as libc::c_int as libc::c_ushort,
            high: 0x138 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13a as libc::c_int as libc::c_ushort,
            high: 0x13a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13c as libc::c_int as libc::c_ushort,
            high: 0x13c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13e as libc::c_int as libc::c_ushort,
            high: 0x13e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x140 as libc::c_int as libc::c_ushort,
            high: 0x140 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x142 as libc::c_int as libc::c_ushort,
            high: 0x142 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x144 as libc::c_int as libc::c_ushort,
            high: 0x144 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x146 as libc::c_int as libc::c_ushort,
            high: 0x146 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x148 as libc::c_int as libc::c_ushort,
            high: 0x149 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14b as libc::c_int as libc::c_ushort,
            high: 0x14b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14d as libc::c_int as libc::c_ushort,
            high: 0x14d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14f as libc::c_int as libc::c_ushort,
            high: 0x14f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x151 as libc::c_int as libc::c_ushort,
            high: 0x151 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x153 as libc::c_int as libc::c_ushort,
            high: 0x153 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x155 as libc::c_int as libc::c_ushort,
            high: 0x155 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x157 as libc::c_int as libc::c_ushort,
            high: 0x157 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x159 as libc::c_int as libc::c_ushort,
            high: 0x159 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15b as libc::c_int as libc::c_ushort,
            high: 0x15b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15d as libc::c_int as libc::c_ushort,
            high: 0x15d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15f as libc::c_int as libc::c_ushort,
            high: 0x15f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x161 as libc::c_int as libc::c_ushort,
            high: 0x161 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x163 as libc::c_int as libc::c_ushort,
            high: 0x163 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x165 as libc::c_int as libc::c_ushort,
            high: 0x165 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x167 as libc::c_int as libc::c_ushort,
            high: 0x167 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x169 as libc::c_int as libc::c_ushort,
            high: 0x169 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16b as libc::c_int as libc::c_ushort,
            high: 0x16b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16d as libc::c_int as libc::c_ushort,
            high: 0x16d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16f as libc::c_int as libc::c_ushort,
            high: 0x16f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x171 as libc::c_int as libc::c_ushort,
            high: 0x171 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x173 as libc::c_int as libc::c_ushort,
            high: 0x173 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x175 as libc::c_int as libc::c_ushort,
            high: 0x175 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x177 as libc::c_int as libc::c_ushort,
            high: 0x177 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17a as libc::c_int as libc::c_ushort,
            high: 0x17a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17c as libc::c_int as libc::c_ushort,
            high: 0x17c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17e as libc::c_int as libc::c_ushort,
            high: 0x180 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x183 as libc::c_int as libc::c_ushort,
            high: 0x183 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x185 as libc::c_int as libc::c_ushort,
            high: 0x185 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x188 as libc::c_int as libc::c_ushort,
            high: 0x188 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x18c as libc::c_int as libc::c_ushort,
            high: 0x18d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x192 as libc::c_int as libc::c_ushort,
            high: 0x192 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x195 as libc::c_int as libc::c_ushort,
            high: 0x195 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x199 as libc::c_int as libc::c_ushort,
            high: 0x19b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x19e as libc::c_int as libc::c_ushort,
            high: 0x19e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a1 as libc::c_int as libc::c_ushort,
            high: 0x1a1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a3 as libc::c_int as libc::c_ushort,
            high: 0x1a3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a5 as libc::c_int as libc::c_ushort,
            high: 0x1a5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a8 as libc::c_int as libc::c_ushort,
            high: 0x1a8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1aa as libc::c_int as libc::c_ushort,
            high: 0x1ab as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ad as libc::c_int as libc::c_ushort,
            high: 0x1ad as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b0 as libc::c_int as libc::c_ushort,
            high: 0x1b0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b4 as libc::c_int as libc::c_ushort,
            high: 0x1b4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b6 as libc::c_int as libc::c_ushort,
            high: 0x1b6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b9 as libc::c_int as libc::c_ushort,
            high: 0x1ba as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1bd as libc::c_int as libc::c_ushort,
            high: 0x1bf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c6 as libc::c_int as libc::c_ushort,
            high: 0x1c6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c9 as libc::c_int as libc::c_ushort,
            high: 0x1c9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1cc as libc::c_int as libc::c_ushort,
            high: 0x1cc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ce as libc::c_int as libc::c_ushort,
            high: 0x1ce as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d0 as libc::c_int as libc::c_ushort,
            high: 0x1d0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d2 as libc::c_int as libc::c_ushort,
            high: 0x1d2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d4 as libc::c_int as libc::c_ushort,
            high: 0x1d4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d6 as libc::c_int as libc::c_ushort,
            high: 0x1d6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d8 as libc::c_int as libc::c_ushort,
            high: 0x1d8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1da as libc::c_int as libc::c_ushort,
            high: 0x1da as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1dc as libc::c_int as libc::c_ushort,
            high: 0x1dd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1df as libc::c_int as libc::c_ushort,
            high: 0x1df as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1 as libc::c_int as libc::c_ushort,
            high: 0x1e1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3 as libc::c_int as libc::c_ushort,
            high: 0x1e3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5 as libc::c_int as libc::c_ushort,
            high: 0x1e5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7 as libc::c_int as libc::c_ushort,
            high: 0x1e7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e9 as libc::c_int as libc::c_ushort,
            high: 0x1e9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb as libc::c_int as libc::c_ushort,
            high: 0x1eb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed as libc::c_int as libc::c_ushort,
            high: 0x1ed as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef as libc::c_int as libc::c_ushort,
            high: 0x1f0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f3 as libc::c_int as libc::c_ushort,
            high: 0x1f3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5 as libc::c_int as libc::c_ushort,
            high: 0x1f5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f9 as libc::c_int as libc::c_ushort,
            high: 0x1f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fb as libc::c_int as libc::c_ushort,
            high: 0x1fb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd as libc::c_int as libc::c_ushort,
            high: 0x1fd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff as libc::c_int as libc::c_ushort,
            high: 0x1ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x201 as libc::c_int as libc::c_ushort,
            high: 0x201 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x203 as libc::c_int as libc::c_ushort,
            high: 0x203 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x205 as libc::c_int as libc::c_ushort,
            high: 0x205 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207 as libc::c_int as libc::c_ushort,
            high: 0x207 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x209 as libc::c_int as libc::c_ushort,
            high: 0x209 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20b as libc::c_int as libc::c_ushort,
            high: 0x20b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20d as libc::c_int as libc::c_ushort,
            high: 0x20d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20f as libc::c_int as libc::c_ushort,
            high: 0x20f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x211 as libc::c_int as libc::c_ushort,
            high: 0x211 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213 as libc::c_int as libc::c_ushort,
            high: 0x213 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x215 as libc::c_int as libc::c_ushort,
            high: 0x215 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x217 as libc::c_int as libc::c_ushort,
            high: 0x217 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x219 as libc::c_int as libc::c_ushort,
            high: 0x219 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21b as libc::c_int as libc::c_ushort,
            high: 0x21b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d as libc::c_int as libc::c_ushort,
            high: 0x21d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21f as libc::c_int as libc::c_ushort,
            high: 0x21f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x221 as libc::c_int as libc::c_ushort,
            high: 0x221 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x223 as libc::c_int as libc::c_ushort,
            high: 0x223 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x225 as libc::c_int as libc::c_ushort,
            high: 0x225 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x227 as libc::c_int as libc::c_ushort,
            high: 0x227 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x229 as libc::c_int as libc::c_ushort,
            high: 0x229 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22b as libc::c_int as libc::c_ushort,
            high: 0x22b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22d as libc::c_int as libc::c_ushort,
            high: 0x22d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22f as libc::c_int as libc::c_ushort,
            high: 0x22f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x231 as libc::c_int as libc::c_ushort,
            high: 0x231 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x233 as libc::c_int as libc::c_ushort,
            high: 0x236 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x250 as libc::c_int as libc::c_ushort,
            high: 0x2af as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x390 as libc::c_int as libc::c_ushort,
            high: 0x390 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ac as libc::c_int as libc::c_ushort,
            high: 0x3ce as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d0 as libc::c_int as libc::c_ushort,
            high: 0x3d1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d5 as libc::c_int as libc::c_ushort,
            high: 0x3d7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d9 as libc::c_int as libc::c_ushort,
            high: 0x3d9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3db as libc::c_int as libc::c_ushort,
            high: 0x3db as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3dd as libc::c_int as libc::c_ushort,
            high: 0x3dd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3df as libc::c_int as libc::c_ushort,
            high: 0x3df as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e1 as libc::c_int as libc::c_ushort,
            high: 0x3e1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e3 as libc::c_int as libc::c_ushort,
            high: 0x3e3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e5 as libc::c_int as libc::c_ushort,
            high: 0x3e5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e7 as libc::c_int as libc::c_ushort,
            high: 0x3e7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e9 as libc::c_int as libc::c_ushort,
            high: 0x3e9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3eb as libc::c_int as libc::c_ushort,
            high: 0x3eb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ed as libc::c_int as libc::c_ushort,
            high: 0x3ed as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ef as libc::c_int as libc::c_ushort,
            high: 0x3f3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f5 as libc::c_int as libc::c_ushort,
            high: 0x3f5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f8 as libc::c_int as libc::c_ushort,
            high: 0x3f8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3fb as libc::c_int as libc::c_ushort,
            high: 0x3fb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x430 as libc::c_int as libc::c_ushort,
            high: 0x45f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x461 as libc::c_int as libc::c_ushort,
            high: 0x461 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x463 as libc::c_int as libc::c_ushort,
            high: 0x463 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x465 as libc::c_int as libc::c_ushort,
            high: 0x465 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x467 as libc::c_int as libc::c_ushort,
            high: 0x467 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x469 as libc::c_int as libc::c_ushort,
            high: 0x469 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46b as libc::c_int as libc::c_ushort,
            high: 0x46b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46d as libc::c_int as libc::c_ushort,
            high: 0x46d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46f as libc::c_int as libc::c_ushort,
            high: 0x46f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x471 as libc::c_int as libc::c_ushort,
            high: 0x471 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x473 as libc::c_int as libc::c_ushort,
            high: 0x473 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x475 as libc::c_int as libc::c_ushort,
            high: 0x475 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x477 as libc::c_int as libc::c_ushort,
            high: 0x477 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x479 as libc::c_int as libc::c_ushort,
            high: 0x479 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47b as libc::c_int as libc::c_ushort,
            high: 0x47b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47d as libc::c_int as libc::c_ushort,
            high: 0x47d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47f as libc::c_int as libc::c_ushort,
            high: 0x47f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x481 as libc::c_int as libc::c_ushort,
            high: 0x481 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48b as libc::c_int as libc::c_ushort,
            high: 0x48b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48d as libc::c_int as libc::c_ushort,
            high: 0x48d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48f as libc::c_int as libc::c_ushort,
            high: 0x48f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x491 as libc::c_int as libc::c_ushort,
            high: 0x491 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x493 as libc::c_int as libc::c_ushort,
            high: 0x493 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x495 as libc::c_int as libc::c_ushort,
            high: 0x495 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x497 as libc::c_int as libc::c_ushort,
            high: 0x497 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x499 as libc::c_int as libc::c_ushort,
            high: 0x499 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49b as libc::c_int as libc::c_ushort,
            high: 0x49b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49d as libc::c_int as libc::c_ushort,
            high: 0x49d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49f as libc::c_int as libc::c_ushort,
            high: 0x49f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a1 as libc::c_int as libc::c_ushort,
            high: 0x4a1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a3 as libc::c_int as libc::c_ushort,
            high: 0x4a3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a5 as libc::c_int as libc::c_ushort,
            high: 0x4a5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a7 as libc::c_int as libc::c_ushort,
            high: 0x4a7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a9 as libc::c_int as libc::c_ushort,
            high: 0x4a9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ab as libc::c_int as libc::c_ushort,
            high: 0x4ab as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ad as libc::c_int as libc::c_ushort,
            high: 0x4ad as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4af as libc::c_int as libc::c_ushort,
            high: 0x4af as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b1 as libc::c_int as libc::c_ushort,
            high: 0x4b1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b3 as libc::c_int as libc::c_ushort,
            high: 0x4b3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b5 as libc::c_int as libc::c_ushort,
            high: 0x4b5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b7 as libc::c_int as libc::c_ushort,
            high: 0x4b7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b9 as libc::c_int as libc::c_ushort,
            high: 0x4b9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4bb as libc::c_int as libc::c_ushort,
            high: 0x4bb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4bd as libc::c_int as libc::c_ushort,
            high: 0x4bd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4bf as libc::c_int as libc::c_ushort,
            high: 0x4bf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c2 as libc::c_int as libc::c_ushort,
            high: 0x4c2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c4 as libc::c_int as libc::c_ushort,
            high: 0x4c4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c6 as libc::c_int as libc::c_ushort,
            high: 0x4c6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c8 as libc::c_int as libc::c_ushort,
            high: 0x4c8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ca as libc::c_int as libc::c_ushort,
            high: 0x4ca as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4cc as libc::c_int as libc::c_ushort,
            high: 0x4cc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ce as libc::c_int as libc::c_ushort,
            high: 0x4ce as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d1 as libc::c_int as libc::c_ushort,
            high: 0x4d1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d3 as libc::c_int as libc::c_ushort,
            high: 0x4d3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d5 as libc::c_int as libc::c_ushort,
            high: 0x4d5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d7 as libc::c_int as libc::c_ushort,
            high: 0x4d7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d9 as libc::c_int as libc::c_ushort,
            high: 0x4d9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4db as libc::c_int as libc::c_ushort,
            high: 0x4db as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4dd as libc::c_int as libc::c_ushort,
            high: 0x4dd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4df as libc::c_int as libc::c_ushort,
            high: 0x4df as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e1 as libc::c_int as libc::c_ushort,
            high: 0x4e1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e3 as libc::c_int as libc::c_ushort,
            high: 0x4e3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e5 as libc::c_int as libc::c_ushort,
            high: 0x4e5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e7 as libc::c_int as libc::c_ushort,
            high: 0x4e7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e9 as libc::c_int as libc::c_ushort,
            high: 0x4e9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4eb as libc::c_int as libc::c_ushort,
            high: 0x4eb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ed as libc::c_int as libc::c_ushort,
            high: 0x4ed as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ef as libc::c_int as libc::c_ushort,
            high: 0x4ef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f1 as libc::c_int as libc::c_ushort,
            high: 0x4f1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f3 as libc::c_int as libc::c_ushort,
            high: 0x4f3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f5 as libc::c_int as libc::c_ushort,
            high: 0x4f5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f9 as libc::c_int as libc::c_ushort,
            high: 0x4f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x501 as libc::c_int as libc::c_ushort,
            high: 0x501 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x503 as libc::c_int as libc::c_ushort,
            high: 0x503 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x505 as libc::c_int as libc::c_ushort,
            high: 0x505 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x507 as libc::c_int as libc::c_ushort,
            high: 0x507 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x509 as libc::c_int as libc::c_ushort,
            high: 0x509 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50b as libc::c_int as libc::c_ushort,
            high: 0x50b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50d as libc::c_int as libc::c_ushort,
            high: 0x50d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50f as libc::c_int as libc::c_ushort,
            high: 0x50f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x561 as libc::c_int as libc::c_ushort,
            high: 0x587 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d00 as libc::c_int as libc::c_ushort,
            high: 0x1d2b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d62 as libc::c_int as libc::c_ushort,
            high: 0x1d6b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e01 as libc::c_int as libc::c_ushort,
            high: 0x1e01 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e03 as libc::c_int as libc::c_ushort,
            high: 0x1e03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e05 as libc::c_int as libc::c_ushort,
            high: 0x1e05 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e07 as libc::c_int as libc::c_ushort,
            high: 0x1e07 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e09 as libc::c_int as libc::c_ushort,
            high: 0x1e09 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0b as libc::c_int as libc::c_ushort,
            high: 0x1e0b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0d as libc::c_int as libc::c_ushort,
            high: 0x1e0d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0f as libc::c_int as libc::c_ushort,
            high: 0x1e0f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e11 as libc::c_int as libc::c_ushort,
            high: 0x1e11 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e13 as libc::c_int as libc::c_ushort,
            high: 0x1e13 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e15 as libc::c_int as libc::c_ushort,
            high: 0x1e15 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e17 as libc::c_int as libc::c_ushort,
            high: 0x1e17 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e19 as libc::c_int as libc::c_ushort,
            high: 0x1e19 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1b as libc::c_int as libc::c_ushort,
            high: 0x1e1b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1d as libc::c_int as libc::c_ushort,
            high: 0x1e1d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1f as libc::c_int as libc::c_ushort,
            high: 0x1e1f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e21 as libc::c_int as libc::c_ushort,
            high: 0x1e21 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e23 as libc::c_int as libc::c_ushort,
            high: 0x1e23 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e25 as libc::c_int as libc::c_ushort,
            high: 0x1e25 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e27 as libc::c_int as libc::c_ushort,
            high: 0x1e27 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e29 as libc::c_int as libc::c_ushort,
            high: 0x1e29 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2b as libc::c_int as libc::c_ushort,
            high: 0x1e2b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2d as libc::c_int as libc::c_ushort,
            high: 0x1e2d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2f as libc::c_int as libc::c_ushort,
            high: 0x1e2f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e31 as libc::c_int as libc::c_ushort,
            high: 0x1e31 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e33 as libc::c_int as libc::c_ushort,
            high: 0x1e33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e35 as libc::c_int as libc::c_ushort,
            high: 0x1e35 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e37 as libc::c_int as libc::c_ushort,
            high: 0x1e37 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e39 as libc::c_int as libc::c_ushort,
            high: 0x1e39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3b as libc::c_int as libc::c_ushort,
            high: 0x1e3b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3d as libc::c_int as libc::c_ushort,
            high: 0x1e3d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3f as libc::c_int as libc::c_ushort,
            high: 0x1e3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e41 as libc::c_int as libc::c_ushort,
            high: 0x1e41 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e43 as libc::c_int as libc::c_ushort,
            high: 0x1e43 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e45 as libc::c_int as libc::c_ushort,
            high: 0x1e45 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e47 as libc::c_int as libc::c_ushort,
            high: 0x1e47 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e49 as libc::c_int as libc::c_ushort,
            high: 0x1e49 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4b as libc::c_int as libc::c_ushort,
            high: 0x1e4b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4d as libc::c_int as libc::c_ushort,
            high: 0x1e4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4f as libc::c_int as libc::c_ushort,
            high: 0x1e4f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e51 as libc::c_int as libc::c_ushort,
            high: 0x1e51 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e53 as libc::c_int as libc::c_ushort,
            high: 0x1e53 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e55 as libc::c_int as libc::c_ushort,
            high: 0x1e55 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e57 as libc::c_int as libc::c_ushort,
            high: 0x1e57 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e59 as libc::c_int as libc::c_ushort,
            high: 0x1e59 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5b as libc::c_int as libc::c_ushort,
            high: 0x1e5b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5d as libc::c_int as libc::c_ushort,
            high: 0x1e5d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5f as libc::c_int as libc::c_ushort,
            high: 0x1e5f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e61 as libc::c_int as libc::c_ushort,
            high: 0x1e61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e63 as libc::c_int as libc::c_ushort,
            high: 0x1e63 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e65 as libc::c_int as libc::c_ushort,
            high: 0x1e65 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e67 as libc::c_int as libc::c_ushort,
            high: 0x1e67 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e69 as libc::c_int as libc::c_ushort,
            high: 0x1e69 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6b as libc::c_int as libc::c_ushort,
            high: 0x1e6b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6d as libc::c_int as libc::c_ushort,
            high: 0x1e6d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6f as libc::c_int as libc::c_ushort,
            high: 0x1e6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e71 as libc::c_int as libc::c_ushort,
            high: 0x1e71 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e73 as libc::c_int as libc::c_ushort,
            high: 0x1e73 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e75 as libc::c_int as libc::c_ushort,
            high: 0x1e75 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e77 as libc::c_int as libc::c_ushort,
            high: 0x1e77 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e79 as libc::c_int as libc::c_ushort,
            high: 0x1e79 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7b as libc::c_int as libc::c_ushort,
            high: 0x1e7b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7d as libc::c_int as libc::c_ushort,
            high: 0x1e7d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7f as libc::c_int as libc::c_ushort,
            high: 0x1e7f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e81 as libc::c_int as libc::c_ushort,
            high: 0x1e81 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e83 as libc::c_int as libc::c_ushort,
            high: 0x1e83 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e85 as libc::c_int as libc::c_ushort,
            high: 0x1e85 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e87 as libc::c_int as libc::c_ushort,
            high: 0x1e87 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e89 as libc::c_int as libc::c_ushort,
            high: 0x1e89 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8b as libc::c_int as libc::c_ushort,
            high: 0x1e8b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8d as libc::c_int as libc::c_ushort,
            high: 0x1e8d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8f as libc::c_int as libc::c_ushort,
            high: 0x1e8f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e91 as libc::c_int as libc::c_ushort,
            high: 0x1e91 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e93 as libc::c_int as libc::c_ushort,
            high: 0x1e93 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e95 as libc::c_int as libc::c_ushort,
            high: 0x1e9b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea1 as libc::c_int as libc::c_ushort,
            high: 0x1ea1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea3 as libc::c_int as libc::c_ushort,
            high: 0x1ea3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea5 as libc::c_int as libc::c_ushort,
            high: 0x1ea5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea7 as libc::c_int as libc::c_ushort,
            high: 0x1ea7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea9 as libc::c_int as libc::c_ushort,
            high: 0x1ea9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eab as libc::c_int as libc::c_ushort,
            high: 0x1eab as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ead as libc::c_int as libc::c_ushort,
            high: 0x1ead as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eaf as libc::c_int as libc::c_ushort,
            high: 0x1eaf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb1 as libc::c_int as libc::c_ushort,
            high: 0x1eb1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb3 as libc::c_int as libc::c_ushort,
            high: 0x1eb3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb5 as libc::c_int as libc::c_ushort,
            high: 0x1eb5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb7 as libc::c_int as libc::c_ushort,
            high: 0x1eb7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb9 as libc::c_int as libc::c_ushort,
            high: 0x1eb9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ebb as libc::c_int as libc::c_ushort,
            high: 0x1ebb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ebd as libc::c_int as libc::c_ushort,
            high: 0x1ebd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ebf as libc::c_int as libc::c_ushort,
            high: 0x1ebf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec1 as libc::c_int as libc::c_ushort,
            high: 0x1ec1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec3 as libc::c_int as libc::c_ushort,
            high: 0x1ec3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec5 as libc::c_int as libc::c_ushort,
            high: 0x1ec5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec7 as libc::c_int as libc::c_ushort,
            high: 0x1ec7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec9 as libc::c_int as libc::c_ushort,
            high: 0x1ec9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ecb as libc::c_int as libc::c_ushort,
            high: 0x1ecb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ecd as libc::c_int as libc::c_ushort,
            high: 0x1ecd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ecf as libc::c_int as libc::c_ushort,
            high: 0x1ecf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed1 as libc::c_int as libc::c_ushort,
            high: 0x1ed1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed3 as libc::c_int as libc::c_ushort,
            high: 0x1ed3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed5 as libc::c_int as libc::c_ushort,
            high: 0x1ed5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed7 as libc::c_int as libc::c_ushort,
            high: 0x1ed7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed9 as libc::c_int as libc::c_ushort,
            high: 0x1ed9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1edb as libc::c_int as libc::c_ushort,
            high: 0x1edb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1edd as libc::c_int as libc::c_ushort,
            high: 0x1edd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1edf as libc::c_int as libc::c_ushort,
            high: 0x1edf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee1 as libc::c_int as libc::c_ushort,
            high: 0x1ee1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee3 as libc::c_int as libc::c_ushort,
            high: 0x1ee3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee5 as libc::c_int as libc::c_ushort,
            high: 0x1ee5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee7 as libc::c_int as libc::c_ushort,
            high: 0x1ee7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee9 as libc::c_int as libc::c_ushort,
            high: 0x1ee9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eeb as libc::c_int as libc::c_ushort,
            high: 0x1eeb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eed as libc::c_int as libc::c_ushort,
            high: 0x1eed as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eef as libc::c_int as libc::c_ushort,
            high: 0x1eef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef1 as libc::c_int as libc::c_ushort,
            high: 0x1ef1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef3 as libc::c_int as libc::c_ushort,
            high: 0x1ef3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef5 as libc::c_int as libc::c_ushort,
            high: 0x1ef5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef7 as libc::c_int as libc::c_ushort,
            high: 0x1ef7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef9 as libc::c_int as libc::c_ushort,
            high: 0x1ef9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f00 as libc::c_int as libc::c_ushort,
            high: 0x1f07 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f10 as libc::c_int as libc::c_ushort,
            high: 0x1f15 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f20 as libc::c_int as libc::c_ushort,
            high: 0x1f27 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f30 as libc::c_int as libc::c_ushort,
            high: 0x1f37 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f40 as libc::c_int as libc::c_ushort,
            high: 0x1f45 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f50 as libc::c_int as libc::c_ushort,
            high: 0x1f57 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f60 as libc::c_int as libc::c_ushort,
            high: 0x1f67 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f70 as libc::c_int as libc::c_ushort,
            high: 0x1f7d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f80 as libc::c_int as libc::c_ushort,
            high: 0x1f87 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f90 as libc::c_int as libc::c_ushort,
            high: 0x1f97 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fa0 as libc::c_int as libc::c_ushort,
            high: 0x1fa7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fb0 as libc::c_int as libc::c_ushort,
            high: 0x1fb4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fb6 as libc::c_int as libc::c_ushort,
            high: 0x1fb7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbe as libc::c_int as libc::c_ushort,
            high: 0x1fbe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc2 as libc::c_int as libc::c_ushort,
            high: 0x1fc4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc6 as libc::c_int as libc::c_ushort,
            high: 0x1fc7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd0 as libc::c_int as libc::c_ushort,
            high: 0x1fd3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd6 as libc::c_int as libc::c_ushort,
            high: 0x1fd7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fe0 as libc::c_int as libc::c_ushort,
            high: 0x1fe7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff2 as libc::c_int as libc::c_ushort,
            high: 0x1ff4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff6 as libc::c_int as libc::c_ushort,
            high: 0x1ff7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2071 as libc::c_int as libc::c_ushort,
            high: 0x2071 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207f as libc::c_int as libc::c_ushort,
            high: 0x207f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x210a as libc::c_int as libc::c_ushort,
            high: 0x210a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x210e as libc::c_int as libc::c_ushort,
            high: 0x210f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2113 as libc::c_int as libc::c_ushort,
            high: 0x2113 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212f as libc::c_int as libc::c_ushort,
            high: 0x212f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2134 as libc::c_int as libc::c_ushort,
            high: 0x2134 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2139 as libc::c_int as libc::c_ushort,
            high: 0x2139 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213d as libc::c_int as libc::c_ushort,
            high: 0x213d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2146 as libc::c_int as libc::c_ushort,
            high: 0x2149 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb00 as libc::c_int as libc::c_ushort,
            high: 0xfb06 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb13 as libc::c_int as libc::c_ushort,
            high: 0xfb17 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff41 as libc::c_int as libc::c_ushort,
            high: 0xff5a as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlLlL: [xmlChLRange; 28] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10428 as libc::c_int as libc::c_uint,
            high: 0x1044f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d41a as libc::c_int as libc::c_uint,
            high: 0x1d433 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d44e as libc::c_int as libc::c_uint,
            high: 0x1d454 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d456 as libc::c_int as libc::c_uint,
            high: 0x1d467 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d482 as libc::c_int as libc::c_uint,
            high: 0x1d49b as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4b6 as libc::c_int as libc::c_uint,
            high: 0x1d4b9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4bb as libc::c_int as libc::c_uint,
            high: 0x1d4bb as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4bd as libc::c_int as libc::c_uint,
            high: 0x1d4c3 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4c5 as libc::c_int as libc::c_uint,
            high: 0x1d4cf as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4ea as libc::c_int as libc::c_uint,
            high: 0x1d503 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d51e as libc::c_int as libc::c_uint,
            high: 0x1d537 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d552 as libc::c_int as libc::c_uint,
            high: 0x1d56b as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d586 as libc::c_int as libc::c_uint,
            high: 0x1d59f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d5ba as libc::c_int as libc::c_uint,
            high: 0x1d5d3 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d5ee as libc::c_int as libc::c_uint,
            high: 0x1d607 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d622 as libc::c_int as libc::c_uint,
            high: 0x1d63b as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d656 as libc::c_int as libc::c_uint,
            high: 0x1d66f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d68a as libc::c_int as libc::c_uint,
            high: 0x1d6a3 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6c2 as libc::c_int as libc::c_uint,
            high: 0x1d6da as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6dc as libc::c_int as libc::c_uint,
            high: 0x1d6e1 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6fc as libc::c_int as libc::c_uint,
            high: 0x1d714 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d716 as libc::c_int as libc::c_uint,
            high: 0x1d71b as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d736 as libc::c_int as libc::c_uint,
            high: 0x1d74e as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d750 as libc::c_int as libc::c_uint,
            high: 0x1d755 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d770 as libc::c_int as libc::c_uint,
            high: 0x1d788 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d78a as libc::c_int as libc::c_uint,
            high: 0x1d78f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7aa as libc::c_int as libc::c_uint,
            high: 0x1d7c2 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7c4 as libc::c_int as libc::c_uint,
            high: 0x1d7c9 as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlLlG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 396 as libc::c_int,
            nbLongRange: 28 as libc::c_int,
            shortRange: xmlLlS.as_ptr(),
            longRange: xmlLlL.as_ptr(),
        };
        init
    }
};
static mut xmlLmS: [xmlChSRange; 20] = [
    {
        let mut init = _xmlChSRange {
            low: 0x2b0 as libc::c_int as libc::c_ushort,
            high: 0x2c1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c6 as libc::c_int as libc::c_ushort,
            high: 0x2d1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e0 as libc::c_int as libc::c_ushort,
            high: 0x2e4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ee as libc::c_int as libc::c_ushort,
            high: 0x2ee as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x37a as libc::c_int as libc::c_ushort,
            high: 0x37a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x559 as libc::c_int as libc::c_ushort,
            high: 0x559 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x640 as libc::c_int as libc::c_ushort,
            high: 0x640 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e5 as libc::c_int as libc::c_ushort,
            high: 0x6e6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe46 as libc::c_int as libc::c_ushort,
            high: 0xe46 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec6 as libc::c_int as libc::c_ushort,
            high: 0xec6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d7 as libc::c_int as libc::c_ushort,
            high: 0x17d7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1843 as libc::c_int as libc::c_ushort,
            high: 0x1843 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d2c as libc::c_int as libc::c_ushort,
            high: 0x1d61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3005 as libc::c_int as libc::c_ushort,
            high: 0x3005 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3031 as libc::c_int as libc::c_ushort,
            high: 0x3035 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303b as libc::c_int as libc::c_ushort,
            high: 0x303b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309d as libc::c_int as libc::c_ushort,
            high: 0x309e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30fc as libc::c_int as libc::c_ushort,
            high: 0x30fe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff70 as libc::c_int as libc::c_ushort,
            high: 0xff70 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff9e as libc::c_int as libc::c_ushort,
            high: 0xff9f as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlLmG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 20 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlLmS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlLoS: [xmlChSRange; 211] = [
    {
        let mut init = _xmlChSRange {
            low: 0x1bb as libc::c_int as libc::c_ushort,
            high: 0x1bb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c0 as libc::c_int as libc::c_ushort,
            high: 0x1c3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5d0 as libc::c_int as libc::c_ushort,
            high: 0x5ea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5f0 as libc::c_int as libc::c_ushort,
            high: 0x5f2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x621 as libc::c_int as libc::c_ushort,
            high: 0x63a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x641 as libc::c_int as libc::c_ushort,
            high: 0x64a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x66e as libc::c_int as libc::c_ushort,
            high: 0x66f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x671 as libc::c_int as libc::c_ushort,
            high: 0x6d3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d5 as libc::c_int as libc::c_ushort,
            high: 0x6d5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ee as libc::c_int as libc::c_ushort,
            high: 0x6ef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6fa as libc::c_int as libc::c_ushort,
            high: 0x6fc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ff as libc::c_int as libc::c_ushort,
            high: 0x6ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x710 as libc::c_int as libc::c_ushort,
            high: 0x710 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x712 as libc::c_int as libc::c_ushort,
            high: 0x72f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x74d as libc::c_int as libc::c_ushort,
            high: 0x74f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x780 as libc::c_int as libc::c_ushort,
            high: 0x7a5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7b1 as libc::c_int as libc::c_ushort,
            high: 0x7b1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x904 as libc::c_int as libc::c_ushort,
            high: 0x939 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93d as libc::c_int as libc::c_ushort,
            high: 0x93d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x950 as libc::c_int as libc::c_ushort,
            high: 0x950 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x958 as libc::c_int as libc::c_ushort,
            high: 0x961 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x985 as libc::c_int as libc::c_ushort,
            high: 0x98c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x98f as libc::c_int as libc::c_ushort,
            high: 0x990 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x993 as libc::c_int as libc::c_ushort,
            high: 0x9a8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9aa as libc::c_int as libc::c_ushort,
            high: 0x9b0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9b2 as libc::c_int as libc::c_ushort,
            high: 0x9b2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9b6 as libc::c_int as libc::c_ushort,
            high: 0x9b9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9bd as libc::c_int as libc::c_ushort,
            high: 0x9bd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9dc as libc::c_int as libc::c_ushort,
            high: 0x9dd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9df as libc::c_int as libc::c_ushort,
            high: 0x9e1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f0 as libc::c_int as libc::c_ushort,
            high: 0x9f1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa05 as libc::c_int as libc::c_ushort,
            high: 0xa0a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa0f as libc::c_int as libc::c_ushort,
            high: 0xa10 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa13 as libc::c_int as libc::c_ushort,
            high: 0xa28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa2a as libc::c_int as libc::c_ushort,
            high: 0xa30 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa32 as libc::c_int as libc::c_ushort,
            high: 0xa33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa35 as libc::c_int as libc::c_ushort,
            high: 0xa36 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa38 as libc::c_int as libc::c_ushort,
            high: 0xa39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa59 as libc::c_int as libc::c_ushort,
            high: 0xa5c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa5e as libc::c_int as libc::c_ushort,
            high: 0xa5e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa72 as libc::c_int as libc::c_ushort,
            high: 0xa74 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa85 as libc::c_int as libc::c_ushort,
            high: 0xa8d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa8f as libc::c_int as libc::c_ushort,
            high: 0xa91 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa93 as libc::c_int as libc::c_ushort,
            high: 0xaa8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaaa as libc::c_int as libc::c_ushort,
            high: 0xab0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xab2 as libc::c_int as libc::c_ushort,
            high: 0xab3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xab5 as libc::c_int as libc::c_ushort,
            high: 0xab9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabd as libc::c_int as libc::c_ushort,
            high: 0xabd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xad0 as libc::c_int as libc::c_ushort,
            high: 0xad0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae0 as libc::c_int as libc::c_ushort,
            high: 0xae1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb05 as libc::c_int as libc::c_ushort,
            high: 0xb0c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb0f as libc::c_int as libc::c_ushort,
            high: 0xb10 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb13 as libc::c_int as libc::c_ushort,
            high: 0xb28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb2a as libc::c_int as libc::c_ushort,
            high: 0xb30 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb32 as libc::c_int as libc::c_ushort,
            high: 0xb33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb35 as libc::c_int as libc::c_ushort,
            high: 0xb39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3d as libc::c_int as libc::c_ushort,
            high: 0xb3d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5c as libc::c_int as libc::c_ushort,
            high: 0xb5d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb5f as libc::c_int as libc::c_ushort,
            high: 0xb61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb71 as libc::c_int as libc::c_ushort,
            high: 0xb71 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb83 as libc::c_int as libc::c_ushort,
            high: 0xb83 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb85 as libc::c_int as libc::c_ushort,
            high: 0xb8a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb8e as libc::c_int as libc::c_ushort,
            high: 0xb90 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb92 as libc::c_int as libc::c_ushort,
            high: 0xb95 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb99 as libc::c_int as libc::c_ushort,
            high: 0xb9a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9c as libc::c_int as libc::c_ushort,
            high: 0xb9c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9e as libc::c_int as libc::c_ushort,
            high: 0xb9f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba3 as libc::c_int as libc::c_ushort,
            high: 0xba4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xba8 as libc::c_int as libc::c_ushort,
            high: 0xbaa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbae as libc::c_int as libc::c_ushort,
            high: 0xbb5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbb7 as libc::c_int as libc::c_ushort,
            high: 0xbb9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc05 as libc::c_int as libc::c_ushort,
            high: 0xc0c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc0e as libc::c_int as libc::c_ushort,
            high: 0xc10 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc12 as libc::c_int as libc::c_ushort,
            high: 0xc28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc2a as libc::c_int as libc::c_ushort,
            high: 0xc33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc35 as libc::c_int as libc::c_ushort,
            high: 0xc39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc60 as libc::c_int as libc::c_ushort,
            high: 0xc61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc85 as libc::c_int as libc::c_ushort,
            high: 0xc8c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc8e as libc::c_int as libc::c_ushort,
            high: 0xc90 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc92 as libc::c_int as libc::c_ushort,
            high: 0xca8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcaa as libc::c_int as libc::c_ushort,
            high: 0xcb3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcb5 as libc::c_int as libc::c_ushort,
            high: 0xcb9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbd as libc::c_int as libc::c_ushort,
            high: 0xcbd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcde as libc::c_int as libc::c_ushort,
            high: 0xcde as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xce0 as libc::c_int as libc::c_ushort,
            high: 0xce1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd05 as libc::c_int as libc::c_ushort,
            high: 0xd0c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd0e as libc::c_int as libc::c_ushort,
            high: 0xd10 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd12 as libc::c_int as libc::c_ushort,
            high: 0xd28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd2a as libc::c_int as libc::c_ushort,
            high: 0xd39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd60 as libc::c_int as libc::c_ushort,
            high: 0xd61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd85 as libc::c_int as libc::c_ushort,
            high: 0xd96 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd9a as libc::c_int as libc::c_ushort,
            high: 0xdb1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdb3 as libc::c_int as libc::c_ushort,
            high: 0xdbb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdbd as libc::c_int as libc::c_ushort,
            high: 0xdbd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdc0 as libc::c_int as libc::c_ushort,
            high: 0xdc6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe01 as libc::c_int as libc::c_ushort,
            high: 0xe30 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe32 as libc::c_int as libc::c_ushort,
            high: 0xe33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe40 as libc::c_int as libc::c_ushort,
            high: 0xe45 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe81 as libc::c_int as libc::c_ushort,
            high: 0xe82 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe84 as libc::c_int as libc::c_ushort,
            high: 0xe84 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe87 as libc::c_int as libc::c_ushort,
            high: 0xe88 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe8a as libc::c_int as libc::c_ushort,
            high: 0xe8a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe8d as libc::c_int as libc::c_ushort,
            high: 0xe8d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe94 as libc::c_int as libc::c_ushort,
            high: 0xe97 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe99 as libc::c_int as libc::c_ushort,
            high: 0xe9f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea1 as libc::c_int as libc::c_ushort,
            high: 0xea3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea5 as libc::c_int as libc::c_ushort,
            high: 0xea5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xea7 as libc::c_int as libc::c_ushort,
            high: 0xea7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeaa as libc::c_int as libc::c_ushort,
            high: 0xeab as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xead as libc::c_int as libc::c_ushort,
            high: 0xeb0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb2 as libc::c_int as libc::c_ushort,
            high: 0xeb3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xebd as libc::c_int as libc::c_ushort,
            high: 0xebd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec0 as libc::c_int as libc::c_ushort,
            high: 0xec4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xedc as libc::c_int as libc::c_ushort,
            high: 0xedd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf00 as libc::c_int as libc::c_ushort,
            high: 0xf00 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf40 as libc::c_int as libc::c_ushort,
            high: 0xf47 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf49 as libc::c_int as libc::c_ushort,
            high: 0xf6a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf88 as libc::c_int as libc::c_ushort,
            high: 0xf8b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1000 as libc::c_int as libc::c_ushort,
            high: 0x1021 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1023 as libc::c_int as libc::c_ushort,
            high: 0x1027 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1029 as libc::c_int as libc::c_ushort,
            high: 0x102a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1050 as libc::c_int as libc::c_ushort,
            high: 0x1055 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10d0 as libc::c_int as libc::c_ushort,
            high: 0x10f8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1100 as libc::c_int as libc::c_ushort,
            high: 0x1159 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x115f as libc::c_int as libc::c_ushort,
            high: 0x11a2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11a8 as libc::c_int as libc::c_ushort,
            high: 0x11f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1200 as libc::c_int as libc::c_ushort,
            high: 0x1206 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1208 as libc::c_int as libc::c_ushort,
            high: 0x1246 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1248 as libc::c_int as libc::c_ushort,
            high: 0x1248 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x124a as libc::c_int as libc::c_ushort,
            high: 0x124d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1250 as libc::c_int as libc::c_ushort,
            high: 0x1256 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1258 as libc::c_int as libc::c_ushort,
            high: 0x1258 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x125a as libc::c_int as libc::c_ushort,
            high: 0x125d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1260 as libc::c_int as libc::c_ushort,
            high: 0x1286 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1288 as libc::c_int as libc::c_ushort,
            high: 0x1288 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x128a as libc::c_int as libc::c_ushort,
            high: 0x128d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1290 as libc::c_int as libc::c_ushort,
            high: 0x12ae as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b0 as libc::c_int as libc::c_ushort,
            high: 0x12b0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b2 as libc::c_int as libc::c_ushort,
            high: 0x12b5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12b8 as libc::c_int as libc::c_ushort,
            high: 0x12be as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c0 as libc::c_int as libc::c_ushort,
            high: 0x12c0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c2 as libc::c_int as libc::c_ushort,
            high: 0x12c5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c8 as libc::c_int as libc::c_ushort,
            high: 0x12ce as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12d0 as libc::c_int as libc::c_ushort,
            high: 0x12d6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12d8 as libc::c_int as libc::c_ushort,
            high: 0x12ee as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12f0 as libc::c_int as libc::c_ushort,
            high: 0x130e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1310 as libc::c_int as libc::c_ushort,
            high: 0x1310 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1312 as libc::c_int as libc::c_ushort,
            high: 0x1315 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1318 as libc::c_int as libc::c_ushort,
            high: 0x131e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1320 as libc::c_int as libc::c_ushort,
            high: 0x1346 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1348 as libc::c_int as libc::c_ushort,
            high: 0x135a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13a0 as libc::c_int as libc::c_ushort,
            high: 0x13f4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1401 as libc::c_int as libc::c_ushort,
            high: 0x166c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x166f as libc::c_int as libc::c_ushort,
            high: 0x1676 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1681 as libc::c_int as libc::c_ushort,
            high: 0x169a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16a0 as libc::c_int as libc::c_ushort,
            high: 0x16ea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1700 as libc::c_int as libc::c_ushort,
            high: 0x170c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x170e as libc::c_int as libc::c_ushort,
            high: 0x1711 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1720 as libc::c_int as libc::c_ushort,
            high: 0x1731 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1740 as libc::c_int as libc::c_ushort,
            high: 0x1751 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1760 as libc::c_int as libc::c_ushort,
            high: 0x176c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x176e as libc::c_int as libc::c_ushort,
            high: 0x1770 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1780 as libc::c_int as libc::c_ushort,
            high: 0x17b3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17dc as libc::c_int as libc::c_ushort,
            high: 0x17dc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1820 as libc::c_int as libc::c_ushort,
            high: 0x1842 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1844 as libc::c_int as libc::c_ushort,
            high: 0x1877 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1880 as libc::c_int as libc::c_ushort,
            high: 0x18a8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1900 as libc::c_int as libc::c_ushort,
            high: 0x191c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1950 as libc::c_int as libc::c_ushort,
            high: 0x196d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1970 as libc::c_int as libc::c_ushort,
            high: 0x1974 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2135 as libc::c_int as libc::c_ushort,
            high: 0x2138 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3006 as libc::c_int as libc::c_ushort,
            high: 0x3006 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303c as libc::c_int as libc::c_ushort,
            high: 0x303c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3041 as libc::c_int as libc::c_ushort,
            high: 0x3096 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309f as libc::c_int as libc::c_ushort,
            high: 0x309f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30a1 as libc::c_int as libc::c_ushort,
            high: 0x30fa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30ff as libc::c_int as libc::c_ushort,
            high: 0x30ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3105 as libc::c_int as libc::c_ushort,
            high: 0x312c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3131 as libc::c_int as libc::c_ushort,
            high: 0x318e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x31a0 as libc::c_int as libc::c_ushort,
            high: 0x31b7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x31f0 as libc::c_int as libc::c_ushort,
            high: 0x31ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3400 as libc::c_int as libc::c_ushort,
            high: 0x3400 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4db5 as libc::c_int as libc::c_ushort,
            high: 0x4db5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e00 as libc::c_int as libc::c_ushort,
            high: 0x4e00 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9fa5 as libc::c_int as libc::c_ushort,
            high: 0x9fa5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa000 as libc::c_int as libc::c_ushort,
            high: 0xa48c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac00 as libc::c_int as libc::c_ushort,
            high: 0xac00 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd7a3 as libc::c_int as libc::c_ushort,
            high: 0xd7a3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf900 as libc::c_int as libc::c_ushort,
            high: 0xfa2d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfa30 as libc::c_int as libc::c_ushort,
            high: 0xfa6a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1d as libc::c_int as libc::c_ushort,
            high: 0xfb1d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1f as libc::c_int as libc::c_ushort,
            high: 0xfb28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb2a as libc::c_int as libc::c_ushort,
            high: 0xfb36 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb38 as libc::c_int as libc::c_ushort,
            high: 0xfb3c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb3e as libc::c_int as libc::c_ushort,
            high: 0xfb3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb40 as libc::c_int as libc::c_ushort,
            high: 0xfb41 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb43 as libc::c_int as libc::c_ushort,
            high: 0xfb44 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb46 as libc::c_int as libc::c_ushort,
            high: 0xfbb1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfbd3 as libc::c_int as libc::c_ushort,
            high: 0xfd3d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd50 as libc::c_int as libc::c_ushort,
            high: 0xfd8f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd92 as libc::c_int as libc::c_ushort,
            high: 0xfdc7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfdf0 as libc::c_int as libc::c_ushort,
            high: 0xfdfb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe70 as libc::c_int as libc::c_ushort,
            high: 0xfe74 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe76 as libc::c_int as libc::c_ushort,
            high: 0xfefc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff66 as libc::c_int as libc::c_ushort,
            high: 0xff6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff71 as libc::c_int as libc::c_ushort,
            high: 0xff9d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffa0 as libc::c_int as libc::c_ushort,
            high: 0xffbe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffc2 as libc::c_int as libc::c_ushort,
            high: 0xffc7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffca as libc::c_int as libc::c_ushort,
            high: 0xffcf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffd2 as libc::c_int as libc::c_ushort,
            high: 0xffd7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffda as libc::c_int as libc::c_ushort,
            high: 0xffdc as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlLoL: [xmlChLRange; 20] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10000 as libc::c_int as libc::c_uint,
            high: 0x1000b as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1000d as libc::c_int as libc::c_uint,
            high: 0x10026 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10028 as libc::c_int as libc::c_uint,
            high: 0x1003a as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1003c as libc::c_int as libc::c_uint,
            high: 0x1003d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1003f as libc::c_int as libc::c_uint,
            high: 0x1004d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10050 as libc::c_int as libc::c_uint,
            high: 0x1005d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10080 as libc::c_int as libc::c_uint,
            high: 0x100fa as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10300 as libc::c_int as libc::c_uint,
            high: 0x1031e as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10330 as libc::c_int as libc::c_uint,
            high: 0x10349 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10380 as libc::c_int as libc::c_uint,
            high: 0x1039d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10450 as libc::c_int as libc::c_uint,
            high: 0x1049d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10800 as libc::c_int as libc::c_uint,
            high: 0x10805 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10808 as libc::c_int as libc::c_uint,
            high: 0x10808 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1080a as libc::c_int as libc::c_uint,
            high: 0x10835 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10837 as libc::c_int as libc::c_uint,
            high: 0x10838 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1083c as libc::c_int as libc::c_uint,
            high: 0x1083c as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1083f as libc::c_int as libc::c_uint,
            high: 0x1083f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x20000 as libc::c_int as libc::c_uint,
            high: 0x20000 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x2a6d6 as libc::c_int as libc::c_uint,
            high: 0x2a6d6 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x2f800 as libc::c_int as libc::c_uint,
            high: 0x2fa1d as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlLoG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 211 as libc::c_int,
            nbLongRange: 20 as libc::c_int,
            shortRange: xmlLoS.as_ptr(),
            longRange: xmlLoL.as_ptr(),
        };
        init
    }
};
static mut xmlLtS: [xmlChSRange; 10] = [
    {
        let mut init = _xmlChSRange {
            low: 0x1c5 as libc::c_int as libc::c_ushort,
            high: 0x1c5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c8 as libc::c_int as libc::c_ushort,
            high: 0x1c8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1cb as libc::c_int as libc::c_ushort,
            high: 0x1cb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f2 as libc::c_int as libc::c_ushort,
            high: 0x1f2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f88 as libc::c_int as libc::c_ushort,
            high: 0x1f8f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f98 as libc::c_int as libc::c_ushort,
            high: 0x1f9f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fa8 as libc::c_int as libc::c_ushort,
            high: 0x1faf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbc as libc::c_int as libc::c_ushort,
            high: 0x1fbc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fcc as libc::c_int as libc::c_ushort,
            high: 0x1fcc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ffc as libc::c_int as libc::c_ushort,
            high: 0x1ffc as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlLtG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 10 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlLtS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlLuS: [xmlChSRange; 390] = [
    {
        let mut init = _xmlChSRange {
            low: 0x41 as libc::c_int as libc::c_ushort,
            high: 0x5a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc0 as libc::c_int as libc::c_ushort,
            high: 0xd6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd8 as libc::c_int as libc::c_ushort,
            high: 0xde as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x100 as libc::c_int as libc::c_ushort,
            high: 0x100 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x102 as libc::c_int as libc::c_ushort,
            high: 0x102 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x104 as libc::c_int as libc::c_ushort,
            high: 0x104 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x106 as libc::c_int as libc::c_ushort,
            high: 0x106 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x108 as libc::c_int as libc::c_ushort,
            high: 0x108 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10a as libc::c_int as libc::c_ushort,
            high: 0x10a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10c as libc::c_int as libc::c_ushort,
            high: 0x10c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10e as libc::c_int as libc::c_ushort,
            high: 0x10e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x110 as libc::c_int as libc::c_ushort,
            high: 0x110 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x112 as libc::c_int as libc::c_ushort,
            high: 0x112 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x114 as libc::c_int as libc::c_ushort,
            high: 0x114 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x116 as libc::c_int as libc::c_ushort,
            high: 0x116 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x118 as libc::c_int as libc::c_ushort,
            high: 0x118 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11a as libc::c_int as libc::c_ushort,
            high: 0x11a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11c as libc::c_int as libc::c_ushort,
            high: 0x11c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11e as libc::c_int as libc::c_ushort,
            high: 0x11e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x120 as libc::c_int as libc::c_ushort,
            high: 0x120 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x122 as libc::c_int as libc::c_ushort,
            high: 0x122 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x124 as libc::c_int as libc::c_ushort,
            high: 0x124 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x126 as libc::c_int as libc::c_ushort,
            high: 0x126 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x128 as libc::c_int as libc::c_ushort,
            high: 0x128 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12a as libc::c_int as libc::c_ushort,
            high: 0x12a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12c as libc::c_int as libc::c_ushort,
            high: 0x12c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x12e as libc::c_int as libc::c_ushort,
            high: 0x12e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x130 as libc::c_int as libc::c_ushort,
            high: 0x130 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x132 as libc::c_int as libc::c_ushort,
            high: 0x132 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x134 as libc::c_int as libc::c_ushort,
            high: 0x134 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x136 as libc::c_int as libc::c_ushort,
            high: 0x136 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x139 as libc::c_int as libc::c_ushort,
            high: 0x139 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13b as libc::c_int as libc::c_ushort,
            high: 0x13b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13d as libc::c_int as libc::c_ushort,
            high: 0x13d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x13f as libc::c_int as libc::c_ushort,
            high: 0x13f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x141 as libc::c_int as libc::c_ushort,
            high: 0x141 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x143 as libc::c_int as libc::c_ushort,
            high: 0x143 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x145 as libc::c_int as libc::c_ushort,
            high: 0x145 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x147 as libc::c_int as libc::c_ushort,
            high: 0x147 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14a as libc::c_int as libc::c_ushort,
            high: 0x14a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14c as libc::c_int as libc::c_ushort,
            high: 0x14c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14e as libc::c_int as libc::c_ushort,
            high: 0x14e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x150 as libc::c_int as libc::c_ushort,
            high: 0x150 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x152 as libc::c_int as libc::c_ushort,
            high: 0x152 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x154 as libc::c_int as libc::c_ushort,
            high: 0x154 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x156 as libc::c_int as libc::c_ushort,
            high: 0x156 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x158 as libc::c_int as libc::c_ushort,
            high: 0x158 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15a as libc::c_int as libc::c_ushort,
            high: 0x15a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15c as libc::c_int as libc::c_ushort,
            high: 0x15c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x15e as libc::c_int as libc::c_ushort,
            high: 0x15e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x160 as libc::c_int as libc::c_ushort,
            high: 0x160 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x162 as libc::c_int as libc::c_ushort,
            high: 0x162 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x164 as libc::c_int as libc::c_ushort,
            high: 0x164 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x166 as libc::c_int as libc::c_ushort,
            high: 0x166 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x168 as libc::c_int as libc::c_ushort,
            high: 0x168 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16a as libc::c_int as libc::c_ushort,
            high: 0x16a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16c as libc::c_int as libc::c_ushort,
            high: 0x16c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16e as libc::c_int as libc::c_ushort,
            high: 0x16e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x170 as libc::c_int as libc::c_ushort,
            high: 0x170 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x172 as libc::c_int as libc::c_ushort,
            high: 0x172 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x174 as libc::c_int as libc::c_ushort,
            high: 0x174 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x176 as libc::c_int as libc::c_ushort,
            high: 0x176 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x178 as libc::c_int as libc::c_ushort,
            high: 0x179 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b as libc::c_int as libc::c_ushort,
            high: 0x17b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d as libc::c_int as libc::c_ushort,
            high: 0x17d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x181 as libc::c_int as libc::c_ushort,
            high: 0x182 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x184 as libc::c_int as libc::c_ushort,
            high: 0x184 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x186 as libc::c_int as libc::c_ushort,
            high: 0x187 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x189 as libc::c_int as libc::c_ushort,
            high: 0x18b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x18e as libc::c_int as libc::c_ushort,
            high: 0x191 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x193 as libc::c_int as libc::c_ushort,
            high: 0x194 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x196 as libc::c_int as libc::c_ushort,
            high: 0x198 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x19c as libc::c_int as libc::c_ushort,
            high: 0x19d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x19f as libc::c_int as libc::c_ushort,
            high: 0x1a0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a2 as libc::c_int as libc::c_ushort,
            high: 0x1a2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a4 as libc::c_int as libc::c_ushort,
            high: 0x1a4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a6 as libc::c_int as libc::c_ushort,
            high: 0x1a7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1a9 as libc::c_int as libc::c_ushort,
            high: 0x1a9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ac as libc::c_int as libc::c_ushort,
            high: 0x1ac as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ae as libc::c_int as libc::c_ushort,
            high: 0x1af as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b1 as libc::c_int as libc::c_ushort,
            high: 0x1b3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b5 as libc::c_int as libc::c_ushort,
            high: 0x1b5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1b7 as libc::c_int as libc::c_ushort,
            high: 0x1b8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1bc as libc::c_int as libc::c_ushort,
            high: 0x1bc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c4 as libc::c_int as libc::c_ushort,
            high: 0x1c4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1c7 as libc::c_int as libc::c_ushort,
            high: 0x1c7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ca as libc::c_int as libc::c_ushort,
            high: 0x1ca as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1cd as libc::c_int as libc::c_ushort,
            high: 0x1cd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1cf as libc::c_int as libc::c_ushort,
            high: 0x1cf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d1 as libc::c_int as libc::c_ushort,
            high: 0x1d1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d3 as libc::c_int as libc::c_ushort,
            high: 0x1d3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d5 as libc::c_int as libc::c_ushort,
            high: 0x1d5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d7 as libc::c_int as libc::c_ushort,
            high: 0x1d7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1d9 as libc::c_int as libc::c_ushort,
            high: 0x1d9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1db as libc::c_int as libc::c_ushort,
            high: 0x1db as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1de as libc::c_int as libc::c_ushort,
            high: 0x1de as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0 as libc::c_int as libc::c_ushort,
            high: 0x1e0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2 as libc::c_int as libc::c_ushort,
            high: 0x1e2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4 as libc::c_int as libc::c_ushort,
            high: 0x1e4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6 as libc::c_int as libc::c_ushort,
            high: 0x1e6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8 as libc::c_int as libc::c_ushort,
            high: 0x1e8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea as libc::c_int as libc::c_ushort,
            high: 0x1ea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec as libc::c_int as libc::c_ushort,
            high: 0x1ec as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee as libc::c_int as libc::c_ushort,
            high: 0x1ee as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f1 as libc::c_int as libc::c_ushort,
            high: 0x1f1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f4 as libc::c_int as libc::c_ushort,
            high: 0x1f4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f6 as libc::c_int as libc::c_ushort,
            high: 0x1f8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fa as libc::c_int as libc::c_ushort,
            high: 0x1fa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc as libc::c_int as libc::c_ushort,
            high: 0x1fc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fe as libc::c_int as libc::c_ushort,
            high: 0x1fe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x200 as libc::c_int as libc::c_ushort,
            high: 0x200 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x202 as libc::c_int as libc::c_ushort,
            high: 0x202 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x204 as libc::c_int as libc::c_ushort,
            high: 0x204 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x206 as libc::c_int as libc::c_ushort,
            high: 0x206 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208 as libc::c_int as libc::c_ushort,
            high: 0x208 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20a as libc::c_int as libc::c_ushort,
            high: 0x20a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20c as libc::c_int as libc::c_ushort,
            high: 0x20c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20e as libc::c_int as libc::c_ushort,
            high: 0x20e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x210 as libc::c_int as libc::c_ushort,
            high: 0x210 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212 as libc::c_int as libc::c_ushort,
            high: 0x212 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x214 as libc::c_int as libc::c_ushort,
            high: 0x214 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x216 as libc::c_int as libc::c_ushort,
            high: 0x216 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x218 as libc::c_int as libc::c_ushort,
            high: 0x218 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a as libc::c_int as libc::c_ushort,
            high: 0x21a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21c as libc::c_int as libc::c_ushort,
            high: 0x21c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21e as libc::c_int as libc::c_ushort,
            high: 0x21e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x220 as libc::c_int as libc::c_ushort,
            high: 0x220 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x222 as libc::c_int as libc::c_ushort,
            high: 0x222 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x224 as libc::c_int as libc::c_ushort,
            high: 0x224 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x226 as libc::c_int as libc::c_ushort,
            high: 0x226 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x228 as libc::c_int as libc::c_ushort,
            high: 0x228 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22a as libc::c_int as libc::c_ushort,
            high: 0x22a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22c as libc::c_int as libc::c_ushort,
            high: 0x22c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x22e as libc::c_int as libc::c_ushort,
            high: 0x22e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x230 as libc::c_int as libc::c_ushort,
            high: 0x230 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x232 as libc::c_int as libc::c_ushort,
            high: 0x232 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x386 as libc::c_int as libc::c_ushort,
            high: 0x386 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x388 as libc::c_int as libc::c_ushort,
            high: 0x38a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x38c as libc::c_int as libc::c_ushort,
            high: 0x38c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x38e as libc::c_int as libc::c_ushort,
            high: 0x38f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x391 as libc::c_int as libc::c_ushort,
            high: 0x3a1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3a3 as libc::c_int as libc::c_ushort,
            high: 0x3ab as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d2 as libc::c_int as libc::c_ushort,
            high: 0x3d4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3d8 as libc::c_int as libc::c_ushort,
            high: 0x3d8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3da as libc::c_int as libc::c_ushort,
            high: 0x3da as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3dc as libc::c_int as libc::c_ushort,
            high: 0x3dc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3de as libc::c_int as libc::c_ushort,
            high: 0x3de as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e0 as libc::c_int as libc::c_ushort,
            high: 0x3e0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e2 as libc::c_int as libc::c_ushort,
            high: 0x3e2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e4 as libc::c_int as libc::c_ushort,
            high: 0x3e4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e6 as libc::c_int as libc::c_ushort,
            high: 0x3e6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3e8 as libc::c_int as libc::c_ushort,
            high: 0x3e8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ea as libc::c_int as libc::c_ushort,
            high: 0x3ea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ec as libc::c_int as libc::c_ushort,
            high: 0x3ec as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3ee as libc::c_int as libc::c_ushort,
            high: 0x3ee as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f4 as libc::c_int as libc::c_ushort,
            high: 0x3f4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f7 as libc::c_int as libc::c_ushort,
            high: 0x3f7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f9 as libc::c_int as libc::c_ushort,
            high: 0x3fa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x400 as libc::c_int as libc::c_ushort,
            high: 0x42f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x460 as libc::c_int as libc::c_ushort,
            high: 0x460 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x462 as libc::c_int as libc::c_ushort,
            high: 0x462 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x464 as libc::c_int as libc::c_ushort,
            high: 0x464 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x466 as libc::c_int as libc::c_ushort,
            high: 0x466 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x468 as libc::c_int as libc::c_ushort,
            high: 0x468 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46a as libc::c_int as libc::c_ushort,
            high: 0x46a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46c as libc::c_int as libc::c_ushort,
            high: 0x46c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x46e as libc::c_int as libc::c_ushort,
            high: 0x46e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x470 as libc::c_int as libc::c_ushort,
            high: 0x470 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x472 as libc::c_int as libc::c_ushort,
            high: 0x472 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x474 as libc::c_int as libc::c_ushort,
            high: 0x474 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x476 as libc::c_int as libc::c_ushort,
            high: 0x476 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x478 as libc::c_int as libc::c_ushort,
            high: 0x478 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47a as libc::c_int as libc::c_ushort,
            high: 0x47a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47c as libc::c_int as libc::c_ushort,
            high: 0x47c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x47e as libc::c_int as libc::c_ushort,
            high: 0x47e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x480 as libc::c_int as libc::c_ushort,
            high: 0x480 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48a as libc::c_int as libc::c_ushort,
            high: 0x48a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48c as libc::c_int as libc::c_ushort,
            high: 0x48c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x48e as libc::c_int as libc::c_ushort,
            high: 0x48e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x490 as libc::c_int as libc::c_ushort,
            high: 0x490 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x492 as libc::c_int as libc::c_ushort,
            high: 0x492 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x494 as libc::c_int as libc::c_ushort,
            high: 0x494 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x496 as libc::c_int as libc::c_ushort,
            high: 0x496 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x498 as libc::c_int as libc::c_ushort,
            high: 0x498 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49a as libc::c_int as libc::c_ushort,
            high: 0x49a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49c as libc::c_int as libc::c_ushort,
            high: 0x49c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x49e as libc::c_int as libc::c_ushort,
            high: 0x49e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a0 as libc::c_int as libc::c_ushort,
            high: 0x4a0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a2 as libc::c_int as libc::c_ushort,
            high: 0x4a2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a4 as libc::c_int as libc::c_ushort,
            high: 0x4a4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a6 as libc::c_int as libc::c_ushort,
            high: 0x4a6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4a8 as libc::c_int as libc::c_ushort,
            high: 0x4a8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4aa as libc::c_int as libc::c_ushort,
            high: 0x4aa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ac as libc::c_int as libc::c_ushort,
            high: 0x4ac as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ae as libc::c_int as libc::c_ushort,
            high: 0x4ae as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b0 as libc::c_int as libc::c_ushort,
            high: 0x4b0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b2 as libc::c_int as libc::c_ushort,
            high: 0x4b2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b4 as libc::c_int as libc::c_ushort,
            high: 0x4b4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b6 as libc::c_int as libc::c_ushort,
            high: 0x4b6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4b8 as libc::c_int as libc::c_ushort,
            high: 0x4b8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ba as libc::c_int as libc::c_ushort,
            high: 0x4ba as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4bc as libc::c_int as libc::c_ushort,
            high: 0x4bc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4be as libc::c_int as libc::c_ushort,
            high: 0x4be as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c0 as libc::c_int as libc::c_ushort,
            high: 0x4c1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c3 as libc::c_int as libc::c_ushort,
            high: 0x4c3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c5 as libc::c_int as libc::c_ushort,
            high: 0x4c5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c7 as libc::c_int as libc::c_ushort,
            high: 0x4c7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c9 as libc::c_int as libc::c_ushort,
            high: 0x4c9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4cb as libc::c_int as libc::c_ushort,
            high: 0x4cb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4cd as libc::c_int as libc::c_ushort,
            high: 0x4cd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d0 as libc::c_int as libc::c_ushort,
            high: 0x4d0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d2 as libc::c_int as libc::c_ushort,
            high: 0x4d2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d4 as libc::c_int as libc::c_ushort,
            high: 0x4d4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d6 as libc::c_int as libc::c_ushort,
            high: 0x4d6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d8 as libc::c_int as libc::c_ushort,
            high: 0x4d8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4da as libc::c_int as libc::c_ushort,
            high: 0x4da as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4dc as libc::c_int as libc::c_ushort,
            high: 0x4dc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4de as libc::c_int as libc::c_ushort,
            high: 0x4de as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e0 as libc::c_int as libc::c_ushort,
            high: 0x4e0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e2 as libc::c_int as libc::c_ushort,
            high: 0x4e2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e4 as libc::c_int as libc::c_ushort,
            high: 0x4e4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e6 as libc::c_int as libc::c_ushort,
            high: 0x4e6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4e8 as libc::c_int as libc::c_ushort,
            high: 0x4e8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ea as libc::c_int as libc::c_ushort,
            high: 0x4ea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ec as libc::c_int as libc::c_ushort,
            high: 0x4ec as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ee as libc::c_int as libc::c_ushort,
            high: 0x4ee as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f0 as libc::c_int as libc::c_ushort,
            high: 0x4f0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f2 as libc::c_int as libc::c_ushort,
            high: 0x4f2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f4 as libc::c_int as libc::c_ushort,
            high: 0x4f4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4f8 as libc::c_int as libc::c_ushort,
            high: 0x4f8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x500 as libc::c_int as libc::c_ushort,
            high: 0x500 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x502 as libc::c_int as libc::c_ushort,
            high: 0x502 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x504 as libc::c_int as libc::c_ushort,
            high: 0x504 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x506 as libc::c_int as libc::c_ushort,
            high: 0x506 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x508 as libc::c_int as libc::c_ushort,
            high: 0x508 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50a as libc::c_int as libc::c_ushort,
            high: 0x50a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50c as libc::c_int as libc::c_ushort,
            high: 0x50c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x50e as libc::c_int as libc::c_ushort,
            high: 0x50e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x531 as libc::c_int as libc::c_ushort,
            high: 0x556 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10a0 as libc::c_int as libc::c_ushort,
            high: 0x10c5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e00 as libc::c_int as libc::c_ushort,
            high: 0x1e00 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e02 as libc::c_int as libc::c_ushort,
            high: 0x1e02 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e04 as libc::c_int as libc::c_ushort,
            high: 0x1e04 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e06 as libc::c_int as libc::c_ushort,
            high: 0x1e06 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e08 as libc::c_int as libc::c_ushort,
            high: 0x1e08 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0a as libc::c_int as libc::c_ushort,
            high: 0x1e0a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0c as libc::c_int as libc::c_ushort,
            high: 0x1e0c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e0e as libc::c_int as libc::c_ushort,
            high: 0x1e0e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e10 as libc::c_int as libc::c_ushort,
            high: 0x1e10 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e12 as libc::c_int as libc::c_ushort,
            high: 0x1e12 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e14 as libc::c_int as libc::c_ushort,
            high: 0x1e14 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e16 as libc::c_int as libc::c_ushort,
            high: 0x1e16 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e18 as libc::c_int as libc::c_ushort,
            high: 0x1e18 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1a as libc::c_int as libc::c_ushort,
            high: 0x1e1a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1c as libc::c_int as libc::c_ushort,
            high: 0x1e1c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e1e as libc::c_int as libc::c_ushort,
            high: 0x1e1e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e20 as libc::c_int as libc::c_ushort,
            high: 0x1e20 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e22 as libc::c_int as libc::c_ushort,
            high: 0x1e22 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e24 as libc::c_int as libc::c_ushort,
            high: 0x1e24 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e26 as libc::c_int as libc::c_ushort,
            high: 0x1e26 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e28 as libc::c_int as libc::c_ushort,
            high: 0x1e28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2a as libc::c_int as libc::c_ushort,
            high: 0x1e2a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2c as libc::c_int as libc::c_ushort,
            high: 0x1e2c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e2e as libc::c_int as libc::c_ushort,
            high: 0x1e2e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e30 as libc::c_int as libc::c_ushort,
            high: 0x1e30 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e32 as libc::c_int as libc::c_ushort,
            high: 0x1e32 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e34 as libc::c_int as libc::c_ushort,
            high: 0x1e34 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e36 as libc::c_int as libc::c_ushort,
            high: 0x1e36 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e38 as libc::c_int as libc::c_ushort,
            high: 0x1e38 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3a as libc::c_int as libc::c_ushort,
            high: 0x1e3a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3c as libc::c_int as libc::c_ushort,
            high: 0x1e3c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e3e as libc::c_int as libc::c_ushort,
            high: 0x1e3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e40 as libc::c_int as libc::c_ushort,
            high: 0x1e40 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e42 as libc::c_int as libc::c_ushort,
            high: 0x1e42 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e44 as libc::c_int as libc::c_ushort,
            high: 0x1e44 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e46 as libc::c_int as libc::c_ushort,
            high: 0x1e46 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e48 as libc::c_int as libc::c_ushort,
            high: 0x1e48 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4a as libc::c_int as libc::c_ushort,
            high: 0x1e4a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4c as libc::c_int as libc::c_ushort,
            high: 0x1e4c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e4e as libc::c_int as libc::c_ushort,
            high: 0x1e4e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e50 as libc::c_int as libc::c_ushort,
            high: 0x1e50 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e52 as libc::c_int as libc::c_ushort,
            high: 0x1e52 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e54 as libc::c_int as libc::c_ushort,
            high: 0x1e54 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e56 as libc::c_int as libc::c_ushort,
            high: 0x1e56 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e58 as libc::c_int as libc::c_ushort,
            high: 0x1e58 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5a as libc::c_int as libc::c_ushort,
            high: 0x1e5a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5c as libc::c_int as libc::c_ushort,
            high: 0x1e5c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e5e as libc::c_int as libc::c_ushort,
            high: 0x1e5e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e60 as libc::c_int as libc::c_ushort,
            high: 0x1e60 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e62 as libc::c_int as libc::c_ushort,
            high: 0x1e62 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e64 as libc::c_int as libc::c_ushort,
            high: 0x1e64 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e66 as libc::c_int as libc::c_ushort,
            high: 0x1e66 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e68 as libc::c_int as libc::c_ushort,
            high: 0x1e68 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6a as libc::c_int as libc::c_ushort,
            high: 0x1e6a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6c as libc::c_int as libc::c_ushort,
            high: 0x1e6c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e6e as libc::c_int as libc::c_ushort,
            high: 0x1e6e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e70 as libc::c_int as libc::c_ushort,
            high: 0x1e70 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e72 as libc::c_int as libc::c_ushort,
            high: 0x1e72 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e74 as libc::c_int as libc::c_ushort,
            high: 0x1e74 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e76 as libc::c_int as libc::c_ushort,
            high: 0x1e76 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e78 as libc::c_int as libc::c_ushort,
            high: 0x1e78 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7a as libc::c_int as libc::c_ushort,
            high: 0x1e7a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7c as libc::c_int as libc::c_ushort,
            high: 0x1e7c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e7e as libc::c_int as libc::c_ushort,
            high: 0x1e7e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e80 as libc::c_int as libc::c_ushort,
            high: 0x1e80 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e82 as libc::c_int as libc::c_ushort,
            high: 0x1e82 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e84 as libc::c_int as libc::c_ushort,
            high: 0x1e84 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e86 as libc::c_int as libc::c_ushort,
            high: 0x1e86 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e88 as libc::c_int as libc::c_ushort,
            high: 0x1e88 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8a as libc::c_int as libc::c_ushort,
            high: 0x1e8a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8c as libc::c_int as libc::c_ushort,
            high: 0x1e8c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e8e as libc::c_int as libc::c_ushort,
            high: 0x1e8e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e90 as libc::c_int as libc::c_ushort,
            high: 0x1e90 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e92 as libc::c_int as libc::c_ushort,
            high: 0x1e92 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1e94 as libc::c_int as libc::c_ushort,
            high: 0x1e94 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea0 as libc::c_int as libc::c_ushort,
            high: 0x1ea0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea2 as libc::c_int as libc::c_ushort,
            high: 0x1ea2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea4 as libc::c_int as libc::c_ushort,
            high: 0x1ea4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea6 as libc::c_int as libc::c_ushort,
            high: 0x1ea6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ea8 as libc::c_int as libc::c_ushort,
            high: 0x1ea8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eaa as libc::c_int as libc::c_ushort,
            high: 0x1eaa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eac as libc::c_int as libc::c_ushort,
            high: 0x1eac as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eae as libc::c_int as libc::c_ushort,
            high: 0x1eae as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb0 as libc::c_int as libc::c_ushort,
            high: 0x1eb0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb2 as libc::c_int as libc::c_ushort,
            high: 0x1eb2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb4 as libc::c_int as libc::c_ushort,
            high: 0x1eb4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb6 as libc::c_int as libc::c_ushort,
            high: 0x1eb6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eb8 as libc::c_int as libc::c_ushort,
            high: 0x1eb8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eba as libc::c_int as libc::c_ushort,
            high: 0x1eba as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ebc as libc::c_int as libc::c_ushort,
            high: 0x1ebc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ebe as libc::c_int as libc::c_ushort,
            high: 0x1ebe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec0 as libc::c_int as libc::c_ushort,
            high: 0x1ec0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec2 as libc::c_int as libc::c_ushort,
            high: 0x1ec2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec4 as libc::c_int as libc::c_ushort,
            high: 0x1ec4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec6 as libc::c_int as libc::c_ushort,
            high: 0x1ec6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ec8 as libc::c_int as libc::c_ushort,
            high: 0x1ec8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eca as libc::c_int as libc::c_ushort,
            high: 0x1eca as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ecc as libc::c_int as libc::c_ushort,
            high: 0x1ecc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ece as libc::c_int as libc::c_ushort,
            high: 0x1ece as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed0 as libc::c_int as libc::c_ushort,
            high: 0x1ed0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed2 as libc::c_int as libc::c_ushort,
            high: 0x1ed2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed4 as libc::c_int as libc::c_ushort,
            high: 0x1ed4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed6 as libc::c_int as libc::c_ushort,
            high: 0x1ed6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ed8 as libc::c_int as libc::c_ushort,
            high: 0x1ed8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eda as libc::c_int as libc::c_ushort,
            high: 0x1eda as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1edc as libc::c_int as libc::c_ushort,
            high: 0x1edc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ede as libc::c_int as libc::c_ushort,
            high: 0x1ede as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee0 as libc::c_int as libc::c_ushort,
            high: 0x1ee0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee2 as libc::c_int as libc::c_ushort,
            high: 0x1ee2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee4 as libc::c_int as libc::c_ushort,
            high: 0x1ee4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee6 as libc::c_int as libc::c_ushort,
            high: 0x1ee6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ee8 as libc::c_int as libc::c_ushort,
            high: 0x1ee8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eea as libc::c_int as libc::c_ushort,
            high: 0x1eea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eec as libc::c_int as libc::c_ushort,
            high: 0x1eec as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1eee as libc::c_int as libc::c_ushort,
            high: 0x1eee as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef0 as libc::c_int as libc::c_ushort,
            high: 0x1ef0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef2 as libc::c_int as libc::c_ushort,
            high: 0x1ef2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef4 as libc::c_int as libc::c_ushort,
            high: 0x1ef4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef6 as libc::c_int as libc::c_ushort,
            high: 0x1ef6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ef8 as libc::c_int as libc::c_ushort,
            high: 0x1ef8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f08 as libc::c_int as libc::c_ushort,
            high: 0x1f0f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f18 as libc::c_int as libc::c_ushort,
            high: 0x1f1d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f28 as libc::c_int as libc::c_ushort,
            high: 0x1f2f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f38 as libc::c_int as libc::c_ushort,
            high: 0x1f3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f48 as libc::c_int as libc::c_ushort,
            high: 0x1f4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f59 as libc::c_int as libc::c_ushort,
            high: 0x1f59 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5b as libc::c_int as libc::c_ushort,
            high: 0x1f5b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5d as libc::c_int as libc::c_ushort,
            high: 0x1f5d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f5f as libc::c_int as libc::c_ushort,
            high: 0x1f5f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f68 as libc::c_int as libc::c_ushort,
            high: 0x1f6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fb8 as libc::c_int as libc::c_ushort,
            high: 0x1fbb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fc8 as libc::c_int as libc::c_ushort,
            high: 0x1fcb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fd8 as libc::c_int as libc::c_ushort,
            high: 0x1fdb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fe8 as libc::c_int as libc::c_ushort,
            high: 0x1fec as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ff8 as libc::c_int as libc::c_ushort,
            high: 0x1ffb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2102 as libc::c_int as libc::c_ushort,
            high: 0x2102 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2107 as libc::c_int as libc::c_ushort,
            high: 0x2107 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x210b as libc::c_int as libc::c_ushort,
            high: 0x210d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2110 as libc::c_int as libc::c_ushort,
            high: 0x2112 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2115 as libc::c_int as libc::c_ushort,
            high: 0x2115 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2119 as libc::c_int as libc::c_ushort,
            high: 0x211d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2124 as libc::c_int as libc::c_ushort,
            high: 0x2124 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2126 as libc::c_int as libc::c_ushort,
            high: 0x2126 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2128 as libc::c_int as libc::c_ushort,
            high: 0x2128 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212a as libc::c_int as libc::c_ushort,
            high: 0x212d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2130 as libc::c_int as libc::c_ushort,
            high: 0x2131 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2133 as libc::c_int as libc::c_ushort,
            high: 0x2133 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213e as libc::c_int as libc::c_ushort,
            high: 0x213f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2145 as libc::c_int as libc::c_ushort,
            high: 0x2145 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff21 as libc::c_int as libc::c_ushort,
            high: 0xff3a as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlLuL: [xmlChLRange; 31] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10400 as libc::c_int as libc::c_uint,
            high: 0x10427 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d400 as libc::c_int as libc::c_uint,
            high: 0x1d419 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d434 as libc::c_int as libc::c_uint,
            high: 0x1d44d as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d468 as libc::c_int as libc::c_uint,
            high: 0x1d481 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d49c as libc::c_int as libc::c_uint,
            high: 0x1d49c as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d49e as libc::c_int as libc::c_uint,
            high: 0x1d49f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a2 as libc::c_int as libc::c_uint,
            high: 0x1d4a2 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a5 as libc::c_int as libc::c_uint,
            high: 0x1d4a6 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4a9 as libc::c_int as libc::c_uint,
            high: 0x1d4ac as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4ae as libc::c_int as libc::c_uint,
            high: 0x1d4b5 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d4d0 as libc::c_int as libc::c_uint,
            high: 0x1d4e9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d504 as libc::c_int as libc::c_uint,
            high: 0x1d505 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d507 as libc::c_int as libc::c_uint,
            high: 0x1d50a as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d50d as libc::c_int as libc::c_uint,
            high: 0x1d514 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d516 as libc::c_int as libc::c_uint,
            high: 0x1d51c as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d538 as libc::c_int as libc::c_uint,
            high: 0x1d539 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d53b as libc::c_int as libc::c_uint,
            high: 0x1d53e as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d540 as libc::c_int as libc::c_uint,
            high: 0x1d544 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d546 as libc::c_int as libc::c_uint,
            high: 0x1d546 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d54a as libc::c_int as libc::c_uint,
            high: 0x1d550 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d56c as libc::c_int as libc::c_uint,
            high: 0x1d585 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d5a0 as libc::c_int as libc::c_uint,
            high: 0x1d5b9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d5d4 as libc::c_int as libc::c_uint,
            high: 0x1d5ed as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d608 as libc::c_int as libc::c_uint,
            high: 0x1d621 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d63c as libc::c_int as libc::c_uint,
            high: 0x1d655 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d670 as libc::c_int as libc::c_uint,
            high: 0x1d689 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6a8 as libc::c_int as libc::c_uint,
            high: 0x1d6c0 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6e2 as libc::c_int as libc::c_uint,
            high: 0x1d6fa as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d71c as libc::c_int as libc::c_uint,
            high: 0x1d734 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d756 as libc::c_int as libc::c_uint,
            high: 0x1d76e as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d790 as libc::c_int as libc::c_uint,
            high: 0x1d7a8 as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlLuG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 390 as libc::c_int,
            nbLongRange: 31 as libc::c_int,
            shortRange: xmlLuS.as_ptr(),
            longRange: xmlLuL.as_ptr(),
        };
        init
    }
};
static mut xmlMS: [xmlChSRange; 113] = [
    {
        let mut init = _xmlChSRange {
            low: 0x300 as libc::c_int as libc::c_ushort,
            high: 0x357 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x35d as libc::c_int as libc::c_ushort,
            high: 0x36f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x483 as libc::c_int as libc::c_ushort,
            high: 0x486 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x488 as libc::c_int as libc::c_ushort,
            high: 0x489 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x591 as libc::c_int as libc::c_ushort,
            high: 0x5a1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5a3 as libc::c_int as libc::c_ushort,
            high: 0x5b9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5bb as libc::c_int as libc::c_ushort,
            high: 0x5bd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5bf as libc::c_int as libc::c_ushort,
            high: 0x5bf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c1 as libc::c_int as libc::c_ushort,
            high: 0x5c2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c4 as libc::c_int as libc::c_ushort,
            high: 0x5c4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x610 as libc::c_int as libc::c_ushort,
            high: 0x615 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x64b as libc::c_int as libc::c_ushort,
            high: 0x658 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x670 as libc::c_int as libc::c_ushort,
            high: 0x670 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d6 as libc::c_int as libc::c_ushort,
            high: 0x6dc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6de as libc::c_int as libc::c_ushort,
            high: 0x6e4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e7 as libc::c_int as libc::c_ushort,
            high: 0x6e8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ea as libc::c_int as libc::c_ushort,
            high: 0x6ed as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x711 as libc::c_int as libc::c_ushort,
            high: 0x711 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x730 as libc::c_int as libc::c_ushort,
            high: 0x74a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7a6 as libc::c_int as libc::c_ushort,
            high: 0x7b0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x901 as libc::c_int as libc::c_ushort,
            high: 0x903 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93c as libc::c_int as libc::c_ushort,
            high: 0x93c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93e as libc::c_int as libc::c_ushort,
            high: 0x94d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x951 as libc::c_int as libc::c_ushort,
            high: 0x954 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x962 as libc::c_int as libc::c_ushort,
            high: 0x963 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x981 as libc::c_int as libc::c_ushort,
            high: 0x983 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9bc as libc::c_int as libc::c_ushort,
            high: 0x9bc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9be as libc::c_int as libc::c_ushort,
            high: 0x9c4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9c7 as libc::c_int as libc::c_ushort,
            high: 0x9c8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9cb as libc::c_int as libc::c_ushort,
            high: 0x9cd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9d7 as libc::c_int as libc::c_ushort,
            high: 0x9d7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9e2 as libc::c_int as libc::c_ushort,
            high: 0x9e3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa01 as libc::c_int as libc::c_ushort,
            high: 0xa03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa3c as libc::c_int as libc::c_ushort,
            high: 0xa3c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa3e as libc::c_int as libc::c_ushort,
            high: 0xa42 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa47 as libc::c_int as libc::c_ushort,
            high: 0xa48 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa4b as libc::c_int as libc::c_ushort,
            high: 0xa4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa70 as libc::c_int as libc::c_ushort,
            high: 0xa71 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa81 as libc::c_int as libc::c_ushort,
            high: 0xa83 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabc as libc::c_int as libc::c_ushort,
            high: 0xabc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabe as libc::c_int as libc::c_ushort,
            high: 0xac5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac7 as libc::c_int as libc::c_ushort,
            high: 0xac9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xacb as libc::c_int as libc::c_ushort,
            high: 0xacd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae2 as libc::c_int as libc::c_ushort,
            high: 0xae3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb01 as libc::c_int as libc::c_ushort,
            high: 0xb03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3c as libc::c_int as libc::c_ushort,
            high: 0xb3c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3e as libc::c_int as libc::c_ushort,
            high: 0xb43 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb47 as libc::c_int as libc::c_ushort,
            high: 0xb48 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb4b as libc::c_int as libc::c_ushort,
            high: 0xb4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb56 as libc::c_int as libc::c_ushort,
            high: 0xb57 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb82 as libc::c_int as libc::c_ushort,
            high: 0xb82 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbbe as libc::c_int as libc::c_ushort,
            high: 0xbc2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc6 as libc::c_int as libc::c_ushort,
            high: 0xbc8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbca as libc::c_int as libc::c_ushort,
            high: 0xbcd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbd7 as libc::c_int as libc::c_ushort,
            high: 0xbd7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc01 as libc::c_int as libc::c_ushort,
            high: 0xc03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc3e as libc::c_int as libc::c_ushort,
            high: 0xc44 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc46 as libc::c_int as libc::c_ushort,
            high: 0xc48 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc4a as libc::c_int as libc::c_ushort,
            high: 0xc4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc55 as libc::c_int as libc::c_ushort,
            high: 0xc56 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc82 as libc::c_int as libc::c_ushort,
            high: 0xc83 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbc as libc::c_int as libc::c_ushort,
            high: 0xcbc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbe as libc::c_int as libc::c_ushort,
            high: 0xcc4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcc6 as libc::c_int as libc::c_ushort,
            high: 0xcc8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcca as libc::c_int as libc::c_ushort,
            high: 0xccd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcd5 as libc::c_int as libc::c_ushort,
            high: 0xcd6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd02 as libc::c_int as libc::c_ushort,
            high: 0xd03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd3e as libc::c_int as libc::c_ushort,
            high: 0xd43 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd46 as libc::c_int as libc::c_ushort,
            high: 0xd48 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd4a as libc::c_int as libc::c_ushort,
            high: 0xd4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd57 as libc::c_int as libc::c_ushort,
            high: 0xd57 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd82 as libc::c_int as libc::c_ushort,
            high: 0xd83 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdca as libc::c_int as libc::c_ushort,
            high: 0xdca as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdcf as libc::c_int as libc::c_ushort,
            high: 0xdd4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdd6 as libc::c_int as libc::c_ushort,
            high: 0xdd6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdd8 as libc::c_int as libc::c_ushort,
            high: 0xddf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdf2 as libc::c_int as libc::c_ushort,
            high: 0xdf3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe31 as libc::c_int as libc::c_ushort,
            high: 0xe31 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe34 as libc::c_int as libc::c_ushort,
            high: 0xe3a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe47 as libc::c_int as libc::c_ushort,
            high: 0xe4e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb1 as libc::c_int as libc::c_ushort,
            high: 0xeb1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb4 as libc::c_int as libc::c_ushort,
            high: 0xeb9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xebb as libc::c_int as libc::c_ushort,
            high: 0xebc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec8 as libc::c_int as libc::c_ushort,
            high: 0xecd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf18 as libc::c_int as libc::c_ushort,
            high: 0xf19 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf35 as libc::c_int as libc::c_ushort,
            high: 0xf35 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf37 as libc::c_int as libc::c_ushort,
            high: 0xf37 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf39 as libc::c_int as libc::c_ushort,
            high: 0xf39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3e as libc::c_int as libc::c_ushort,
            high: 0xf3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf71 as libc::c_int as libc::c_ushort,
            high: 0xf84 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf86 as libc::c_int as libc::c_ushort,
            high: 0xf87 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf90 as libc::c_int as libc::c_ushort,
            high: 0xf97 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf99 as libc::c_int as libc::c_ushort,
            high: 0xfbc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfc6 as libc::c_int as libc::c_ushort,
            high: 0xfc6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x102c as libc::c_int as libc::c_ushort,
            high: 0x1032 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1036 as libc::c_int as libc::c_ushort,
            high: 0x1039 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1056 as libc::c_int as libc::c_ushort,
            high: 0x1059 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1712 as libc::c_int as libc::c_ushort,
            high: 0x1714 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1732 as libc::c_int as libc::c_ushort,
            high: 0x1734 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1752 as libc::c_int as libc::c_ushort,
            high: 0x1753 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1772 as libc::c_int as libc::c_ushort,
            high: 0x1773 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b6 as libc::c_int as libc::c_ushort,
            high: 0x17d3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17dd as libc::c_int as libc::c_ushort,
            high: 0x17dd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x180b as libc::c_int as libc::c_ushort,
            high: 0x180d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x18a9 as libc::c_int as libc::c_ushort,
            high: 0x18a9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1920 as libc::c_int as libc::c_ushort,
            high: 0x192b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1930 as libc::c_int as libc::c_ushort,
            high: 0x193b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20d0 as libc::c_int as libc::c_ushort,
            high: 0x20ea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x302a as libc::c_int as libc::c_ushort,
            high: 0x302f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3099 as libc::c_int as libc::c_ushort,
            high: 0x309a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1e as libc::c_int as libc::c_ushort,
            high: 0xfb1e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe00 as libc::c_int as libc::c_ushort,
            high: 0xfe0f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe20 as libc::c_int as libc::c_ushort,
            high: 0xfe23 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlML: [xmlChLRange; 6] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d165 as libc::c_int as libc::c_uint,
            high: 0x1d169 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d16d as libc::c_int as libc::c_uint,
            high: 0x1d172 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d17b as libc::c_int as libc::c_uint,
            high: 0x1d182 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d185 as libc::c_int as libc::c_uint,
            high: 0x1d18b as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d1aa as libc::c_int as libc::c_uint,
            high: 0x1d1ad as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0100 as libc::c_int as libc::c_uint,
            high: 0xe01ef as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlMG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 113 as libc::c_int,
            nbLongRange: 6 as libc::c_int,
            shortRange: xmlMS.as_ptr(),
            longRange: xmlML.as_ptr(),
        };
        init
    }
};
static mut xmlMcS: [xmlChSRange; 55] = [
    {
        let mut init = _xmlChSRange {
            low: 0x903 as libc::c_int as libc::c_ushort,
            high: 0x903 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93e as libc::c_int as libc::c_ushort,
            high: 0x940 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x949 as libc::c_int as libc::c_ushort,
            high: 0x94c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x982 as libc::c_int as libc::c_ushort,
            high: 0x983 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9be as libc::c_int as libc::c_ushort,
            high: 0x9c0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9c7 as libc::c_int as libc::c_ushort,
            high: 0x9c8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9cb as libc::c_int as libc::c_ushort,
            high: 0x9cc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9d7 as libc::c_int as libc::c_ushort,
            high: 0x9d7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa03 as libc::c_int as libc::c_ushort,
            high: 0xa03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa3e as libc::c_int as libc::c_ushort,
            high: 0xa40 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa83 as libc::c_int as libc::c_ushort,
            high: 0xa83 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabe as libc::c_int as libc::c_ushort,
            high: 0xac0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac9 as libc::c_int as libc::c_ushort,
            high: 0xac9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xacb as libc::c_int as libc::c_ushort,
            high: 0xacc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb02 as libc::c_int as libc::c_ushort,
            high: 0xb03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3e as libc::c_int as libc::c_ushort,
            high: 0xb3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb40 as libc::c_int as libc::c_ushort,
            high: 0xb40 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb47 as libc::c_int as libc::c_ushort,
            high: 0xb48 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb4b as libc::c_int as libc::c_ushort,
            high: 0xb4c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb57 as libc::c_int as libc::c_ushort,
            high: 0xb57 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbbe as libc::c_int as libc::c_ushort,
            high: 0xbbf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc1 as libc::c_int as libc::c_ushort,
            high: 0xbc2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc6 as libc::c_int as libc::c_ushort,
            high: 0xbc8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbca as libc::c_int as libc::c_ushort,
            high: 0xbcc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbd7 as libc::c_int as libc::c_ushort,
            high: 0xbd7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc01 as libc::c_int as libc::c_ushort,
            high: 0xc03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc41 as libc::c_int as libc::c_ushort,
            high: 0xc44 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc82 as libc::c_int as libc::c_ushort,
            high: 0xc83 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbe as libc::c_int as libc::c_ushort,
            high: 0xcbe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcc0 as libc::c_int as libc::c_ushort,
            high: 0xcc4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcc7 as libc::c_int as libc::c_ushort,
            high: 0xcc8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcca as libc::c_int as libc::c_ushort,
            high: 0xccb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcd5 as libc::c_int as libc::c_ushort,
            high: 0xcd6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd02 as libc::c_int as libc::c_ushort,
            high: 0xd03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd3e as libc::c_int as libc::c_ushort,
            high: 0xd40 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd46 as libc::c_int as libc::c_ushort,
            high: 0xd48 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd4a as libc::c_int as libc::c_ushort,
            high: 0xd4c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd57 as libc::c_int as libc::c_ushort,
            high: 0xd57 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd82 as libc::c_int as libc::c_ushort,
            high: 0xd83 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdcf as libc::c_int as libc::c_ushort,
            high: 0xdd1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdd8 as libc::c_int as libc::c_ushort,
            high: 0xddf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdf2 as libc::c_int as libc::c_ushort,
            high: 0xdf3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3e as libc::c_int as libc::c_ushort,
            high: 0xf3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf7f as libc::c_int as libc::c_ushort,
            high: 0xf7f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x102c as libc::c_int as libc::c_ushort,
            high: 0x102c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1031 as libc::c_int as libc::c_ushort,
            high: 0x1031 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1038 as libc::c_int as libc::c_ushort,
            high: 0x1038 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1056 as libc::c_int as libc::c_ushort,
            high: 0x1057 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b6 as libc::c_int as libc::c_ushort,
            high: 0x17b6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17be as libc::c_int as libc::c_ushort,
            high: 0x17c5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17c7 as libc::c_int as libc::c_ushort,
            high: 0x17c8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1923 as libc::c_int as libc::c_ushort,
            high: 0x1926 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1929 as libc::c_int as libc::c_ushort,
            high: 0x192b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1930 as libc::c_int as libc::c_ushort,
            high: 0x1931 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1933 as libc::c_int as libc::c_ushort,
            high: 0x1938 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlMcL: [xmlChLRange; 2] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d165 as libc::c_int as libc::c_uint,
            high: 0x1d166 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d16d as libc::c_int as libc::c_uint,
            high: 0x1d172 as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlMcG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 55 as libc::c_int,
            nbLongRange: 2 as libc::c_int,
            shortRange: xmlMcS.as_ptr(),
            longRange: xmlMcL.as_ptr(),
        };
        init
    }
};
static mut xmlMnS: [xmlChSRange; 108] = [
    {
        let mut init = _xmlChSRange {
            low: 0x300 as libc::c_int as libc::c_ushort,
            high: 0x357 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x35d as libc::c_int as libc::c_ushort,
            high: 0x36f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x483 as libc::c_int as libc::c_ushort,
            high: 0x486 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x591 as libc::c_int as libc::c_ushort,
            high: 0x5a1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5a3 as libc::c_int as libc::c_ushort,
            high: 0x5b9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5bb as libc::c_int as libc::c_ushort,
            high: 0x5bd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5bf as libc::c_int as libc::c_ushort,
            high: 0x5bf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c1 as libc::c_int as libc::c_ushort,
            high: 0x5c2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c4 as libc::c_int as libc::c_ushort,
            high: 0x5c4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x610 as libc::c_int as libc::c_ushort,
            high: 0x615 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x64b as libc::c_int as libc::c_ushort,
            high: 0x658 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x670 as libc::c_int as libc::c_ushort,
            high: 0x670 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d6 as libc::c_int as libc::c_ushort,
            high: 0x6dc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6df as libc::c_int as libc::c_ushort,
            high: 0x6e4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e7 as libc::c_int as libc::c_ushort,
            high: 0x6e8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ea as libc::c_int as libc::c_ushort,
            high: 0x6ed as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x711 as libc::c_int as libc::c_ushort,
            high: 0x711 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x730 as libc::c_int as libc::c_ushort,
            high: 0x74a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7a6 as libc::c_int as libc::c_ushort,
            high: 0x7b0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x901 as libc::c_int as libc::c_ushort,
            high: 0x902 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x93c as libc::c_int as libc::c_ushort,
            high: 0x93c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x941 as libc::c_int as libc::c_ushort,
            high: 0x948 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x94d as libc::c_int as libc::c_ushort,
            high: 0x94d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x951 as libc::c_int as libc::c_ushort,
            high: 0x954 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x962 as libc::c_int as libc::c_ushort,
            high: 0x963 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x981 as libc::c_int as libc::c_ushort,
            high: 0x981 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9bc as libc::c_int as libc::c_ushort,
            high: 0x9bc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9c1 as libc::c_int as libc::c_ushort,
            high: 0x9c4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9cd as libc::c_int as libc::c_ushort,
            high: 0x9cd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9e2 as libc::c_int as libc::c_ushort,
            high: 0x9e3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa01 as libc::c_int as libc::c_ushort,
            high: 0xa02 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa3c as libc::c_int as libc::c_ushort,
            high: 0xa3c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa41 as libc::c_int as libc::c_ushort,
            high: 0xa42 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa47 as libc::c_int as libc::c_ushort,
            high: 0xa48 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa4b as libc::c_int as libc::c_ushort,
            high: 0xa4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa70 as libc::c_int as libc::c_ushort,
            high: 0xa71 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa81 as libc::c_int as libc::c_ushort,
            high: 0xa82 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xabc as libc::c_int as libc::c_ushort,
            high: 0xabc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac1 as libc::c_int as libc::c_ushort,
            high: 0xac5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac7 as libc::c_int as libc::c_ushort,
            high: 0xac8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xacd as libc::c_int as libc::c_ushort,
            high: 0xacd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae2 as libc::c_int as libc::c_ushort,
            high: 0xae3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb01 as libc::c_int as libc::c_ushort,
            high: 0xb01 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3c as libc::c_int as libc::c_ushort,
            high: 0xb3c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb3f as libc::c_int as libc::c_ushort,
            high: 0xb3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb41 as libc::c_int as libc::c_ushort,
            high: 0xb43 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb4d as libc::c_int as libc::c_ushort,
            high: 0xb4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb56 as libc::c_int as libc::c_ushort,
            high: 0xb56 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb82 as libc::c_int as libc::c_ushort,
            high: 0xb82 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc0 as libc::c_int as libc::c_ushort,
            high: 0xbc0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbcd as libc::c_int as libc::c_ushort,
            high: 0xbcd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc3e as libc::c_int as libc::c_ushort,
            high: 0xc40 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc46 as libc::c_int as libc::c_ushort,
            high: 0xc48 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc4a as libc::c_int as libc::c_ushort,
            high: 0xc4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc55 as libc::c_int as libc::c_ushort,
            high: 0xc56 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbc as libc::c_int as libc::c_ushort,
            high: 0xcbc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcbf as libc::c_int as libc::c_ushort,
            high: 0xcbf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xcc6 as libc::c_int as libc::c_ushort,
            high: 0xcc6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xccc as libc::c_int as libc::c_ushort,
            high: 0xccd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd41 as libc::c_int as libc::c_ushort,
            high: 0xd43 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd4d as libc::c_int as libc::c_ushort,
            high: 0xd4d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdca as libc::c_int as libc::c_ushort,
            high: 0xdca as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdd2 as libc::c_int as libc::c_ushort,
            high: 0xdd4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdd6 as libc::c_int as libc::c_ushort,
            high: 0xdd6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe31 as libc::c_int as libc::c_ushort,
            high: 0xe31 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe34 as libc::c_int as libc::c_ushort,
            high: 0xe3a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe47 as libc::c_int as libc::c_ushort,
            high: 0xe4e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb1 as libc::c_int as libc::c_ushort,
            high: 0xeb1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb4 as libc::c_int as libc::c_ushort,
            high: 0xeb9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xebb as libc::c_int as libc::c_ushort,
            high: 0xebc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xec8 as libc::c_int as libc::c_ushort,
            high: 0xecd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf18 as libc::c_int as libc::c_ushort,
            high: 0xf19 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf35 as libc::c_int as libc::c_ushort,
            high: 0xf35 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf37 as libc::c_int as libc::c_ushort,
            high: 0xf37 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf39 as libc::c_int as libc::c_ushort,
            high: 0xf39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf71 as libc::c_int as libc::c_ushort,
            high: 0xf7e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf80 as libc::c_int as libc::c_ushort,
            high: 0xf84 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf86 as libc::c_int as libc::c_ushort,
            high: 0xf87 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf90 as libc::c_int as libc::c_ushort,
            high: 0xf97 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf99 as libc::c_int as libc::c_ushort,
            high: 0xfbc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfc6 as libc::c_int as libc::c_ushort,
            high: 0xfc6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x102d as libc::c_int as libc::c_ushort,
            high: 0x1030 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1032 as libc::c_int as libc::c_ushort,
            high: 0x1032 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1036 as libc::c_int as libc::c_ushort,
            high: 0x1037 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1039 as libc::c_int as libc::c_ushort,
            high: 0x1039 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1058 as libc::c_int as libc::c_ushort,
            high: 0x1059 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1712 as libc::c_int as libc::c_ushort,
            high: 0x1714 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1732 as libc::c_int as libc::c_ushort,
            high: 0x1734 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1752 as libc::c_int as libc::c_ushort,
            high: 0x1753 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1772 as libc::c_int as libc::c_ushort,
            high: 0x1773 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17b7 as libc::c_int as libc::c_ushort,
            high: 0x17bd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17c6 as libc::c_int as libc::c_ushort,
            high: 0x17c6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17c9 as libc::c_int as libc::c_ushort,
            high: 0x17d3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17dd as libc::c_int as libc::c_ushort,
            high: 0x17dd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x180b as libc::c_int as libc::c_ushort,
            high: 0x180d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x18a9 as libc::c_int as libc::c_ushort,
            high: 0x18a9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1920 as libc::c_int as libc::c_ushort,
            high: 0x1922 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1927 as libc::c_int as libc::c_ushort,
            high: 0x1928 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1932 as libc::c_int as libc::c_ushort,
            high: 0x1932 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1939 as libc::c_int as libc::c_ushort,
            high: 0x193b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20d0 as libc::c_int as libc::c_ushort,
            high: 0x20dc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20e1 as libc::c_int as libc::c_ushort,
            high: 0x20e1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20e5 as libc::c_int as libc::c_ushort,
            high: 0x20ea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x302a as libc::c_int as libc::c_ushort,
            high: 0x302f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3099 as libc::c_int as libc::c_ushort,
            high: 0x309a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1e as libc::c_int as libc::c_ushort,
            high: 0xfb1e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe00 as libc::c_int as libc::c_ushort,
            high: 0xfe0f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe20 as libc::c_int as libc::c_ushort,
            high: 0xfe23 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlMnL: [xmlChLRange; 5] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d167 as libc::c_int as libc::c_uint,
            high: 0x1d169 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d17b as libc::c_int as libc::c_uint,
            high: 0x1d182 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d185 as libc::c_int as libc::c_uint,
            high: 0x1d18b as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d1aa as libc::c_int as libc::c_uint,
            high: 0x1d1ad as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0xe0100 as libc::c_int as libc::c_uint,
            high: 0xe01ef as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlMnG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 108 as libc::c_int,
            nbLongRange: 5 as libc::c_int,
            shortRange: xmlMnS.as_ptr(),
            longRange: xmlMnL.as_ptr(),
        };
        init
    }
};
static mut xmlNS: [xmlChSRange; 42] = [
    {
        let mut init = _xmlChSRange {
            low: 0x30 as libc::c_int as libc::c_ushort,
            high: 0x39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb2 as libc::c_int as libc::c_ushort,
            high: 0xb3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9 as libc::c_int as libc::c_ushort,
            high: 0xb9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc as libc::c_int as libc::c_ushort,
            high: 0xbe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x660 as libc::c_int as libc::c_ushort,
            high: 0x669 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6f0 as libc::c_int as libc::c_ushort,
            high: 0x6f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x966 as libc::c_int as libc::c_ushort,
            high: 0x96f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9e6 as libc::c_int as libc::c_ushort,
            high: 0x9ef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f4 as libc::c_int as libc::c_ushort,
            high: 0x9f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa66 as libc::c_int as libc::c_ushort,
            high: 0xa6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae6 as libc::c_int as libc::c_ushort,
            high: 0xaef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb66 as libc::c_int as libc::c_ushort,
            high: 0xb6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbe7 as libc::c_int as libc::c_ushort,
            high: 0xbf2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc66 as libc::c_int as libc::c_ushort,
            high: 0xc6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xce6 as libc::c_int as libc::c_ushort,
            high: 0xcef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd66 as libc::c_int as libc::c_ushort,
            high: 0xd6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe50 as libc::c_int as libc::c_ushort,
            high: 0xe59 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xed0 as libc::c_int as libc::c_ushort,
            high: 0xed9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf20 as libc::c_int as libc::c_ushort,
            high: 0xf33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1040 as libc::c_int as libc::c_ushort,
            high: 0x1049 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1369 as libc::c_int as libc::c_ushort,
            high: 0x137c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16ee as libc::c_int as libc::c_ushort,
            high: 0x16f0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17e0 as libc::c_int as libc::c_ushort,
            high: 0x17e9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17f0 as libc::c_int as libc::c_ushort,
            high: 0x17f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1810 as libc::c_int as libc::c_ushort,
            high: 0x1819 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1946 as libc::c_int as libc::c_ushort,
            high: 0x194f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2070 as libc::c_int as libc::c_ushort,
            high: 0x2070 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2074 as libc::c_int as libc::c_ushort,
            high: 0x2079 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2080 as libc::c_int as libc::c_ushort,
            high: 0x2089 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2153 as libc::c_int as libc::c_ushort,
            high: 0x2183 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2460 as libc::c_int as libc::c_ushort,
            high: 0x249b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x24ea as libc::c_int as libc::c_ushort,
            high: 0x24ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2776 as libc::c_int as libc::c_ushort,
            high: 0x2793 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3007 as libc::c_int as libc::c_ushort,
            high: 0x3007 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3021 as libc::c_int as libc::c_ushort,
            high: 0x3029 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3038 as libc::c_int as libc::c_ushort,
            high: 0x303a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3192 as libc::c_int as libc::c_ushort,
            high: 0x3195 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3220 as libc::c_int as libc::c_ushort,
            high: 0x3229 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3251 as libc::c_int as libc::c_ushort,
            high: 0x325f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3280 as libc::c_int as libc::c_ushort,
            high: 0x3289 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x32b1 as libc::c_int as libc::c_ushort,
            high: 0x32bf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff10 as libc::c_int as libc::c_ushort,
            high: 0xff19 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlNL: [xmlChLRange; 5] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10107 as libc::c_int as libc::c_uint,
            high: 0x10133 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10320 as libc::c_int as libc::c_uint,
            high: 0x10323 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1034a as libc::c_int as libc::c_uint,
            high: 0x1034a as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x104a0 as libc::c_int as libc::c_uint,
            high: 0x104a9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7ce as libc::c_int as libc::c_uint,
            high: 0x1d7ff as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlNG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 42 as libc::c_int,
            nbLongRange: 5 as libc::c_int,
            shortRange: xmlNS.as_ptr(),
            longRange: xmlNL.as_ptr(),
        };
        init
    }
};
static mut xmlNdS: [xmlChSRange; 21] = [
    {
        let mut init = _xmlChSRange {
            low: 0x30 as libc::c_int as libc::c_ushort,
            high: 0x39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x660 as libc::c_int as libc::c_ushort,
            high: 0x669 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6f0 as libc::c_int as libc::c_ushort,
            high: 0x6f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x966 as libc::c_int as libc::c_ushort,
            high: 0x96f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9e6 as libc::c_int as libc::c_ushort,
            high: 0x9ef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa66 as libc::c_int as libc::c_ushort,
            high: 0xa6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae6 as libc::c_int as libc::c_ushort,
            high: 0xaef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb66 as libc::c_int as libc::c_ushort,
            high: 0xb6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbe7 as libc::c_int as libc::c_ushort,
            high: 0xbef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xc66 as libc::c_int as libc::c_ushort,
            high: 0xc6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xce6 as libc::c_int as libc::c_ushort,
            high: 0xcef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd66 as libc::c_int as libc::c_ushort,
            high: 0xd6f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe50 as libc::c_int as libc::c_ushort,
            high: 0xe59 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xed0 as libc::c_int as libc::c_ushort,
            high: 0xed9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf20 as libc::c_int as libc::c_ushort,
            high: 0xf29 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1040 as libc::c_int as libc::c_ushort,
            high: 0x1049 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1369 as libc::c_int as libc::c_ushort,
            high: 0x1371 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17e0 as libc::c_int as libc::c_ushort,
            high: 0x17e9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1810 as libc::c_int as libc::c_ushort,
            high: 0x1819 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1946 as libc::c_int as libc::c_ushort,
            high: 0x194f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff10 as libc::c_int as libc::c_ushort,
            high: 0xff19 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlNdL: [xmlChLRange; 2] = [
    {
        let mut init = _xmlChLRange {
            low: 0x104a0 as libc::c_int as libc::c_uint,
            high: 0x104a9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7ce as libc::c_int as libc::c_uint,
            high: 0x1d7ff as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlNdG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 21 as libc::c_int,
            nbLongRange: 2 as libc::c_int,
            shortRange: xmlNdS.as_ptr(),
            longRange: xmlNdL.as_ptr(),
        };
        init
    }
};
static mut xmlNoS: [xmlChSRange; 20] = [
    {
        let mut init = _xmlChSRange {
            low: 0xb2 as libc::c_int as libc::c_ushort,
            high: 0xb3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb9 as libc::c_int as libc::c_ushort,
            high: 0xb9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbc as libc::c_int as libc::c_ushort,
            high: 0xbe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f4 as libc::c_int as libc::c_ushort,
            high: 0x9f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf0 as libc::c_int as libc::c_ushort,
            high: 0xbf2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf2a as libc::c_int as libc::c_ushort,
            high: 0xf33 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1372 as libc::c_int as libc::c_ushort,
            high: 0x137c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17f0 as libc::c_int as libc::c_ushort,
            high: 0x17f9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2070 as libc::c_int as libc::c_ushort,
            high: 0x2070 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2074 as libc::c_int as libc::c_ushort,
            high: 0x2079 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2080 as libc::c_int as libc::c_ushort,
            high: 0x2089 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2153 as libc::c_int as libc::c_ushort,
            high: 0x215f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2460 as libc::c_int as libc::c_ushort,
            high: 0x249b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x24ea as libc::c_int as libc::c_ushort,
            high: 0x24ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2776 as libc::c_int as libc::c_ushort,
            high: 0x2793 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3192 as libc::c_int as libc::c_ushort,
            high: 0x3195 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3220 as libc::c_int as libc::c_ushort,
            high: 0x3229 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3251 as libc::c_int as libc::c_ushort,
            high: 0x325f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3280 as libc::c_int as libc::c_ushort,
            high: 0x3289 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x32b1 as libc::c_int as libc::c_ushort,
            high: 0x32bf as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlNoL: [xmlChLRange; 2] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10107 as libc::c_int as libc::c_uint,
            high: 0x10133 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10320 as libc::c_int as libc::c_uint,
            high: 0x10323 as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlNoG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 20 as libc::c_int,
            nbLongRange: 2 as libc::c_int,
            shortRange: xmlNoS.as_ptr(),
            longRange: xmlNoL.as_ptr(),
        };
        init
    }
};
static mut xmlPS: [xmlChSRange; 84] = [
    {
        let mut init = _xmlChSRange {
            low: 0x21 as libc::c_int as libc::c_ushort,
            high: 0x23 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25 as libc::c_int as libc::c_ushort,
            high: 0x2a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c as libc::c_int as libc::c_ushort,
            high: 0x2f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3a as libc::c_int as libc::c_ushort,
            high: 0x3b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f as libc::c_int as libc::c_ushort,
            high: 0x40 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5b as libc::c_int as libc::c_ushort,
            high: 0x5d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5f as libc::c_int as libc::c_ushort,
            high: 0x5f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7b as libc::c_int as libc::c_ushort,
            high: 0x7b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7d as libc::c_int as libc::c_ushort,
            high: 0x7d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa1 as libc::c_int as libc::c_ushort,
            high: 0xa1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xab as libc::c_int as libc::c_ushort,
            high: 0xab as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb7 as libc::c_int as libc::c_ushort,
            high: 0xb7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbb as libc::c_int as libc::c_ushort,
            high: 0xbb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf as libc::c_int as libc::c_ushort,
            high: 0xbf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x37e as libc::c_int as libc::c_ushort,
            high: 0x37e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x387 as libc::c_int as libc::c_ushort,
            high: 0x387 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x55a as libc::c_int as libc::c_ushort,
            high: 0x55f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x589 as libc::c_int as libc::c_ushort,
            high: 0x58a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5be as libc::c_int as libc::c_ushort,
            high: 0x5be as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c0 as libc::c_int as libc::c_ushort,
            high: 0x5c0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c3 as libc::c_int as libc::c_ushort,
            high: 0x5c3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5f3 as libc::c_int as libc::c_ushort,
            high: 0x5f4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60c as libc::c_int as libc::c_ushort,
            high: 0x60d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x61b as libc::c_int as libc::c_ushort,
            high: 0x61b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x61f as libc::c_int as libc::c_ushort,
            high: 0x61f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x66a as libc::c_int as libc::c_ushort,
            high: 0x66d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d4 as libc::c_int as libc::c_ushort,
            high: 0x6d4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x700 as libc::c_int as libc::c_ushort,
            high: 0x70d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x964 as libc::c_int as libc::c_ushort,
            high: 0x965 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x970 as libc::c_int as libc::c_ushort,
            high: 0x970 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdf4 as libc::c_int as libc::c_ushort,
            high: 0xdf4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe4f as libc::c_int as libc::c_ushort,
            high: 0xe4f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe5a as libc::c_int as libc::c_ushort,
            high: 0xe5b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf04 as libc::c_int as libc::c_ushort,
            high: 0xf12 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3a as libc::c_int as libc::c_ushort,
            high: 0xf3d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf85 as libc::c_int as libc::c_ushort,
            high: 0xf85 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x104a as libc::c_int as libc::c_ushort,
            high: 0x104f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10fb as libc::c_int as libc::c_ushort,
            high: 0x10fb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1361 as libc::c_int as libc::c_ushort,
            high: 0x1368 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x166d as libc::c_int as libc::c_ushort,
            high: 0x166e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x169b as libc::c_int as libc::c_ushort,
            high: 0x169c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16eb as libc::c_int as libc::c_ushort,
            high: 0x16ed as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1735 as libc::c_int as libc::c_ushort,
            high: 0x1736 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d4 as libc::c_int as libc::c_ushort,
            high: 0x17d6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d8 as libc::c_int as libc::c_ushort,
            high: 0x17da as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1800 as libc::c_int as libc::c_ushort,
            high: 0x180a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1944 as libc::c_int as libc::c_ushort,
            high: 0x1945 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2010 as libc::c_int as libc::c_ushort,
            high: 0x2027 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2030 as libc::c_int as libc::c_ushort,
            high: 0x2043 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2045 as libc::c_int as libc::c_ushort,
            high: 0x2051 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2053 as libc::c_int as libc::c_ushort,
            high: 0x2054 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2057 as libc::c_int as libc::c_ushort,
            high: 0x2057 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207d as libc::c_int as libc::c_ushort,
            high: 0x207e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208d as libc::c_int as libc::c_ushort,
            high: 0x208e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2329 as libc::c_int as libc::c_ushort,
            high: 0x232a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b4 as libc::c_int as libc::c_ushort,
            high: 0x23b6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2768 as libc::c_int as libc::c_ushort,
            high: 0x2775 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27e6 as libc::c_int as libc::c_ushort,
            high: 0x27eb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2983 as libc::c_int as libc::c_ushort,
            high: 0x2998 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29d8 as libc::c_int as libc::c_ushort,
            high: 0x29db as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29fc as libc::c_int as libc::c_ushort,
            high: 0x29fd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3001 as libc::c_int as libc::c_ushort,
            high: 0x3003 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3008 as libc::c_int as libc::c_ushort,
            high: 0x3011 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3014 as libc::c_int as libc::c_ushort,
            high: 0x301f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3030 as libc::c_int as libc::c_ushort,
            high: 0x3030 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303d as libc::c_int as libc::c_ushort,
            high: 0x303d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30a0 as libc::c_int as libc::c_ushort,
            high: 0x30a0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30fb as libc::c_int as libc::c_ushort,
            high: 0x30fb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd3e as libc::c_int as libc::c_ushort,
            high: 0xfd3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe30 as libc::c_int as libc::c_ushort,
            high: 0xfe52 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe54 as libc::c_int as libc::c_ushort,
            high: 0xfe61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe63 as libc::c_int as libc::c_ushort,
            high: 0xfe63 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe68 as libc::c_int as libc::c_ushort,
            high: 0xfe68 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe6a as libc::c_int as libc::c_ushort,
            high: 0xfe6b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff01 as libc::c_int as libc::c_ushort,
            high: 0xff03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff05 as libc::c_int as libc::c_ushort,
            high: 0xff0a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0c as libc::c_int as libc::c_ushort,
            high: 0xff0f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1a as libc::c_int as libc::c_ushort,
            high: 0xff1b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1f as libc::c_int as libc::c_ushort,
            high: 0xff20 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3b as libc::c_int as libc::c_ushort,
            high: 0xff3d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3f as libc::c_int as libc::c_ushort,
            high: 0xff3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5b as libc::c_int as libc::c_ushort,
            high: 0xff5b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5d as libc::c_int as libc::c_ushort,
            high: 0xff5d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5f as libc::c_int as libc::c_ushort,
            high: 0xff65 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlPL: [xmlChLRange; 2] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10100 as libc::c_int as libc::c_uint,
            high: 0x10101 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1039f as libc::c_int as libc::c_uint,
            high: 0x1039f as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlPG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 84 as libc::c_int,
            nbLongRange: 2 as libc::c_int,
            shortRange: xmlPS.as_ptr(),
            longRange: xmlPL.as_ptr(),
        };
        init
    }
};
static mut xmlPdS: [xmlChSRange; 11] = [
    {
        let mut init = _xmlChSRange {
            low: 0x2d as libc::c_int as libc::c_ushort,
            high: 0x2d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x58a as libc::c_int as libc::c_ushort,
            high: 0x58a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1806 as libc::c_int as libc::c_ushort,
            high: 0x1806 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2010 as libc::c_int as libc::c_ushort,
            high: 0x2015 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x301c as libc::c_int as libc::c_ushort,
            high: 0x301c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3030 as libc::c_int as libc::c_ushort,
            high: 0x3030 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x30a0 as libc::c_int as libc::c_ushort,
            high: 0x30a0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe31 as libc::c_int as libc::c_ushort,
            high: 0xfe32 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe58 as libc::c_int as libc::c_ushort,
            high: 0xfe58 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe63 as libc::c_int as libc::c_ushort,
            high: 0xfe63 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0d as libc::c_int as libc::c_ushort,
            high: 0xff0d as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlPdG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 11 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlPdS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlPeS: [xmlChSRange; 63] = [
    {
        let mut init = _xmlChSRange {
            low: 0x29 as libc::c_int as libc::c_ushort,
            high: 0x29 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5d as libc::c_int as libc::c_ushort,
            high: 0x5d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7d as libc::c_int as libc::c_ushort,
            high: 0x7d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3b as libc::c_int as libc::c_ushort,
            high: 0xf3b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3d as libc::c_int as libc::c_ushort,
            high: 0xf3d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x169c as libc::c_int as libc::c_ushort,
            high: 0x169c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2046 as libc::c_int as libc::c_ushort,
            high: 0x2046 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207e as libc::c_int as libc::c_ushort,
            high: 0x207e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208e as libc::c_int as libc::c_ushort,
            high: 0x208e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x232a as libc::c_int as libc::c_ushort,
            high: 0x232a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b5 as libc::c_int as libc::c_ushort,
            high: 0x23b5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2769 as libc::c_int as libc::c_ushort,
            high: 0x2769 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276b as libc::c_int as libc::c_ushort,
            high: 0x276b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276d as libc::c_int as libc::c_ushort,
            high: 0x276d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276f as libc::c_int as libc::c_ushort,
            high: 0x276f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2771 as libc::c_int as libc::c_ushort,
            high: 0x2771 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2773 as libc::c_int as libc::c_ushort,
            high: 0x2773 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2775 as libc::c_int as libc::c_ushort,
            high: 0x2775 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27e7 as libc::c_int as libc::c_ushort,
            high: 0x27e7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27e9 as libc::c_int as libc::c_ushort,
            high: 0x27e9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27eb as libc::c_int as libc::c_ushort,
            high: 0x27eb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2984 as libc::c_int as libc::c_ushort,
            high: 0x2984 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2986 as libc::c_int as libc::c_ushort,
            high: 0x2986 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2988 as libc::c_int as libc::c_ushort,
            high: 0x2988 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298a as libc::c_int as libc::c_ushort,
            high: 0x298a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298c as libc::c_int as libc::c_ushort,
            high: 0x298c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298e as libc::c_int as libc::c_ushort,
            high: 0x298e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2990 as libc::c_int as libc::c_ushort,
            high: 0x2990 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2992 as libc::c_int as libc::c_ushort,
            high: 0x2992 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2994 as libc::c_int as libc::c_ushort,
            high: 0x2994 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2996 as libc::c_int as libc::c_ushort,
            high: 0x2996 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2998 as libc::c_int as libc::c_ushort,
            high: 0x2998 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29d9 as libc::c_int as libc::c_ushort,
            high: 0x29d9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29db as libc::c_int as libc::c_ushort,
            high: 0x29db as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29fd as libc::c_int as libc::c_ushort,
            high: 0x29fd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3009 as libc::c_int as libc::c_ushort,
            high: 0x3009 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300b as libc::c_int as libc::c_ushort,
            high: 0x300b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300d as libc::c_int as libc::c_ushort,
            high: 0x300d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300f as libc::c_int as libc::c_ushort,
            high: 0x300f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3011 as libc::c_int as libc::c_ushort,
            high: 0x3011 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3015 as libc::c_int as libc::c_ushort,
            high: 0x3015 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3017 as libc::c_int as libc::c_ushort,
            high: 0x3017 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3019 as libc::c_int as libc::c_ushort,
            high: 0x3019 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x301b as libc::c_int as libc::c_ushort,
            high: 0x301b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x301e as libc::c_int as libc::c_ushort,
            high: 0x301f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd3f as libc::c_int as libc::c_ushort,
            high: 0xfd3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe36 as libc::c_int as libc::c_ushort,
            high: 0xfe36 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe38 as libc::c_int as libc::c_ushort,
            high: 0xfe38 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3a as libc::c_int as libc::c_ushort,
            high: 0xfe3a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3c as libc::c_int as libc::c_ushort,
            high: 0xfe3c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3e as libc::c_int as libc::c_ushort,
            high: 0xfe3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe40 as libc::c_int as libc::c_ushort,
            high: 0xfe40 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe42 as libc::c_int as libc::c_ushort,
            high: 0xfe42 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe44 as libc::c_int as libc::c_ushort,
            high: 0xfe44 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe48 as libc::c_int as libc::c_ushort,
            high: 0xfe48 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5a as libc::c_int as libc::c_ushort,
            high: 0xfe5a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5c as libc::c_int as libc::c_ushort,
            high: 0xfe5c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5e as libc::c_int as libc::c_ushort,
            high: 0xfe5e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff09 as libc::c_int as libc::c_ushort,
            high: 0xff09 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3d as libc::c_int as libc::c_ushort,
            high: 0xff3d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5d as libc::c_int as libc::c_ushort,
            high: 0xff5d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff60 as libc::c_int as libc::c_ushort,
            high: 0xff60 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff63 as libc::c_int as libc::c_ushort,
            high: 0xff63 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlPeG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 63 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlPeS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlPoS: [xmlChSRange; 72] = [
    {
        let mut init = _xmlChSRange {
            low: 0x21 as libc::c_int as libc::c_ushort,
            high: 0x23 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25 as libc::c_int as libc::c_ushort,
            high: 0x27 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2a as libc::c_int as libc::c_ushort,
            high: 0x2a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c as libc::c_int as libc::c_ushort,
            high: 0x2c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e as libc::c_int as libc::c_ushort,
            high: 0x2f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3a as libc::c_int as libc::c_ushort,
            high: 0x3b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f as libc::c_int as libc::c_ushort,
            high: 0x40 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c as libc::c_int as libc::c_ushort,
            high: 0x5c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa1 as libc::c_int as libc::c_ushort,
            high: 0xa1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb7 as libc::c_int as libc::c_ushort,
            high: 0xb7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf as libc::c_int as libc::c_ushort,
            high: 0xbf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x37e as libc::c_int as libc::c_ushort,
            high: 0x37e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x387 as libc::c_int as libc::c_ushort,
            high: 0x387 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x55a as libc::c_int as libc::c_ushort,
            high: 0x55f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x589 as libc::c_int as libc::c_ushort,
            high: 0x589 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5be as libc::c_int as libc::c_ushort,
            high: 0x5be as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c0 as libc::c_int as libc::c_ushort,
            high: 0x5c0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5c3 as libc::c_int as libc::c_ushort,
            high: 0x5c3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5f3 as libc::c_int as libc::c_ushort,
            high: 0x5f4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60c as libc::c_int as libc::c_ushort,
            high: 0x60d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x61b as libc::c_int as libc::c_ushort,
            high: 0x61b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x61f as libc::c_int as libc::c_ushort,
            high: 0x61f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x66a as libc::c_int as libc::c_ushort,
            high: 0x66d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d4 as libc::c_int as libc::c_ushort,
            high: 0x6d4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x700 as libc::c_int as libc::c_ushort,
            high: 0x70d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x964 as libc::c_int as libc::c_ushort,
            high: 0x965 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x970 as libc::c_int as libc::c_ushort,
            high: 0x970 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xdf4 as libc::c_int as libc::c_ushort,
            high: 0xdf4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe4f as libc::c_int as libc::c_ushort,
            high: 0xe4f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe5a as libc::c_int as libc::c_ushort,
            high: 0xe5b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf04 as libc::c_int as libc::c_ushort,
            high: 0xf12 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf85 as libc::c_int as libc::c_ushort,
            high: 0xf85 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x104a as libc::c_int as libc::c_ushort,
            high: 0x104f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x10fb as libc::c_int as libc::c_ushort,
            high: 0x10fb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1361 as libc::c_int as libc::c_ushort,
            high: 0x1368 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x166d as libc::c_int as libc::c_ushort,
            high: 0x166e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x16eb as libc::c_int as libc::c_ushort,
            high: 0x16ed as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1735 as libc::c_int as libc::c_ushort,
            high: 0x1736 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d4 as libc::c_int as libc::c_ushort,
            high: 0x17d6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17d8 as libc::c_int as libc::c_ushort,
            high: 0x17da as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1800 as libc::c_int as libc::c_ushort,
            high: 0x1805 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1807 as libc::c_int as libc::c_ushort,
            high: 0x180a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1944 as libc::c_int as libc::c_ushort,
            high: 0x1945 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2016 as libc::c_int as libc::c_ushort,
            high: 0x2017 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2020 as libc::c_int as libc::c_ushort,
            high: 0x2027 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2030 as libc::c_int as libc::c_ushort,
            high: 0x2038 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x203b as libc::c_int as libc::c_ushort,
            high: 0x203e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2041 as libc::c_int as libc::c_ushort,
            high: 0x2043 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2047 as libc::c_int as libc::c_ushort,
            high: 0x2051 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2053 as libc::c_int as libc::c_ushort,
            high: 0x2053 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2057 as libc::c_int as libc::c_ushort,
            high: 0x2057 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b6 as libc::c_int as libc::c_ushort,
            high: 0x23b6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3001 as libc::c_int as libc::c_ushort,
            high: 0x3003 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303d as libc::c_int as libc::c_ushort,
            high: 0x303d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe30 as libc::c_int as libc::c_ushort,
            high: 0xfe30 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe45 as libc::c_int as libc::c_ushort,
            high: 0xfe46 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe49 as libc::c_int as libc::c_ushort,
            high: 0xfe4c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe50 as libc::c_int as libc::c_ushort,
            high: 0xfe52 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe54 as libc::c_int as libc::c_ushort,
            high: 0xfe57 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5f as libc::c_int as libc::c_ushort,
            high: 0xfe61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe68 as libc::c_int as libc::c_ushort,
            high: 0xfe68 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe6a as libc::c_int as libc::c_ushort,
            high: 0xfe6b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff01 as libc::c_int as libc::c_ushort,
            high: 0xff03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff05 as libc::c_int as libc::c_ushort,
            high: 0xff07 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0a as libc::c_int as libc::c_ushort,
            high: 0xff0a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0c as libc::c_int as libc::c_ushort,
            high: 0xff0c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0e as libc::c_int as libc::c_ushort,
            high: 0xff0f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1a as libc::c_int as libc::c_ushort,
            high: 0xff1b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1f as libc::c_int as libc::c_ushort,
            high: 0xff20 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3c as libc::c_int as libc::c_ushort,
            high: 0xff3c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff61 as libc::c_int as libc::c_ushort,
            high: 0xff61 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff64 as libc::c_int as libc::c_ushort,
            high: 0xff64 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlPoL: [xmlChLRange; 2] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10100 as libc::c_int as libc::c_uint,
            high: 0x10101 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1039f as libc::c_int as libc::c_uint,
            high: 0x1039f as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlPoG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 72 as libc::c_int,
            nbLongRange: 2 as libc::c_int,
            shortRange: xmlPoS.as_ptr(),
            longRange: xmlPoL.as_ptr(),
        };
        init
    }
};
static mut xmlPsS: [xmlChSRange; 65] = [
    {
        let mut init = _xmlChSRange {
            low: 0x28 as libc::c_int as libc::c_ushort,
            high: 0x28 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5b as libc::c_int as libc::c_ushort,
            high: 0x5b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7b as libc::c_int as libc::c_ushort,
            high: 0x7b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3a as libc::c_int as libc::c_ushort,
            high: 0xf3a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3c as libc::c_int as libc::c_ushort,
            high: 0xf3c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x169b as libc::c_int as libc::c_ushort,
            high: 0x169b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x201a as libc::c_int as libc::c_ushort,
            high: 0x201a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x201e as libc::c_int as libc::c_ushort,
            high: 0x201e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2045 as libc::c_int as libc::c_ushort,
            high: 0x2045 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207d as libc::c_int as libc::c_ushort,
            high: 0x207d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208d as libc::c_int as libc::c_ushort,
            high: 0x208d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2329 as libc::c_int as libc::c_ushort,
            high: 0x2329 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b4 as libc::c_int as libc::c_ushort,
            high: 0x23b4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2768 as libc::c_int as libc::c_ushort,
            high: 0x2768 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276a as libc::c_int as libc::c_ushort,
            high: 0x276a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276c as libc::c_int as libc::c_ushort,
            high: 0x276c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x276e as libc::c_int as libc::c_ushort,
            high: 0x276e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2770 as libc::c_int as libc::c_ushort,
            high: 0x2770 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2772 as libc::c_int as libc::c_ushort,
            high: 0x2772 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2774 as libc::c_int as libc::c_ushort,
            high: 0x2774 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27e6 as libc::c_int as libc::c_ushort,
            high: 0x27e6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27e8 as libc::c_int as libc::c_ushort,
            high: 0x27e8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27ea as libc::c_int as libc::c_ushort,
            high: 0x27ea as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2983 as libc::c_int as libc::c_ushort,
            high: 0x2983 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2985 as libc::c_int as libc::c_ushort,
            high: 0x2985 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2987 as libc::c_int as libc::c_ushort,
            high: 0x2987 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2989 as libc::c_int as libc::c_ushort,
            high: 0x2989 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298b as libc::c_int as libc::c_ushort,
            high: 0x298b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298d as libc::c_int as libc::c_ushort,
            high: 0x298d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x298f as libc::c_int as libc::c_ushort,
            high: 0x298f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2991 as libc::c_int as libc::c_ushort,
            high: 0x2991 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2993 as libc::c_int as libc::c_ushort,
            high: 0x2993 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2995 as libc::c_int as libc::c_ushort,
            high: 0x2995 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2997 as libc::c_int as libc::c_ushort,
            high: 0x2997 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29d8 as libc::c_int as libc::c_ushort,
            high: 0x29d8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29da as libc::c_int as libc::c_ushort,
            high: 0x29da as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29fc as libc::c_int as libc::c_ushort,
            high: 0x29fc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3008 as libc::c_int as libc::c_ushort,
            high: 0x3008 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300a as libc::c_int as libc::c_ushort,
            high: 0x300a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300c as libc::c_int as libc::c_ushort,
            high: 0x300c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x300e as libc::c_int as libc::c_ushort,
            high: 0x300e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3010 as libc::c_int as libc::c_ushort,
            high: 0x3010 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3014 as libc::c_int as libc::c_ushort,
            high: 0x3014 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3016 as libc::c_int as libc::c_ushort,
            high: 0x3016 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3018 as libc::c_int as libc::c_ushort,
            high: 0x3018 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x301a as libc::c_int as libc::c_ushort,
            high: 0x301a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x301d as libc::c_int as libc::c_ushort,
            high: 0x301d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfd3e as libc::c_int as libc::c_ushort,
            high: 0xfd3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe35 as libc::c_int as libc::c_ushort,
            high: 0xfe35 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe37 as libc::c_int as libc::c_ushort,
            high: 0xfe37 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe39 as libc::c_int as libc::c_ushort,
            high: 0xfe39 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3b as libc::c_int as libc::c_ushort,
            high: 0xfe3b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3d as libc::c_int as libc::c_ushort,
            high: 0xfe3d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe3f as libc::c_int as libc::c_ushort,
            high: 0xfe3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe41 as libc::c_int as libc::c_ushort,
            high: 0xfe41 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe43 as libc::c_int as libc::c_ushort,
            high: 0xfe43 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe47 as libc::c_int as libc::c_ushort,
            high: 0xfe47 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe59 as libc::c_int as libc::c_ushort,
            high: 0xfe59 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5b as libc::c_int as libc::c_ushort,
            high: 0xfe5b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe5d as libc::c_int as libc::c_ushort,
            high: 0xfe5d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff08 as libc::c_int as libc::c_ushort,
            high: 0xff08 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3b as libc::c_int as libc::c_ushort,
            high: 0xff3b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5b as libc::c_int as libc::c_ushort,
            high: 0xff5b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5f as libc::c_int as libc::c_ushort,
            high: 0xff5f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff62 as libc::c_int as libc::c_ushort,
            high: 0xff62 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlPsG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 65 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlPsS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlSS: [xmlChSRange; 133] = [
    {
        let mut init = _xmlChSRange {
            low: 0x24 as libc::c_int as libc::c_ushort,
            high: 0x24 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2b as libc::c_int as libc::c_ushort,
            high: 0x2b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3c as libc::c_int as libc::c_ushort,
            high: 0x3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x5e as libc::c_int as libc::c_ushort,
            high: 0x5e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60 as libc::c_int as libc::c_ushort,
            high: 0x60 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7c as libc::c_int as libc::c_ushort,
            high: 0x7c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7e as libc::c_int as libc::c_ushort,
            high: 0x7e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa2 as libc::c_int as libc::c_ushort,
            high: 0xa9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac as libc::c_int as libc::c_ushort,
            high: 0xac as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae as libc::c_int as libc::c_ushort,
            high: 0xb1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb4 as libc::c_int as libc::c_ushort,
            high: 0xb4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb6 as libc::c_int as libc::c_ushort,
            high: 0xb6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb8 as libc::c_int as libc::c_ushort,
            high: 0xb8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd7 as libc::c_int as libc::c_ushort,
            high: 0xd7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf7 as libc::c_int as libc::c_ushort,
            high: 0xf7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c2 as libc::c_int as libc::c_ushort,
            high: 0x2c5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2d2 as libc::c_int as libc::c_ushort,
            high: 0x2df as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e5 as libc::c_int as libc::c_ushort,
            high: 0x2ed as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ef as libc::c_int as libc::c_ushort,
            high: 0x2ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x374 as libc::c_int as libc::c_ushort,
            high: 0x375 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x384 as libc::c_int as libc::c_ushort,
            high: 0x385 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f6 as libc::c_int as libc::c_ushort,
            high: 0x3f6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x482 as libc::c_int as libc::c_ushort,
            high: 0x482 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60e as libc::c_int as libc::c_ushort,
            high: 0x60f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e9 as libc::c_int as libc::c_ushort,
            high: 0x6e9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6fd as libc::c_int as libc::c_ushort,
            high: 0x6fe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f2 as libc::c_int as libc::c_ushort,
            high: 0x9f3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9fa as libc::c_int as libc::c_ushort,
            high: 0x9fa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaf1 as libc::c_int as libc::c_ushort,
            high: 0xaf1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb70 as libc::c_int as libc::c_ushort,
            high: 0xb70 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf3 as libc::c_int as libc::c_ushort,
            high: 0xbfa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe3f as libc::c_int as libc::c_ushort,
            high: 0xe3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf01 as libc::c_int as libc::c_ushort,
            high: 0xf03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf13 as libc::c_int as libc::c_ushort,
            high: 0xf17 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf1a as libc::c_int as libc::c_ushort,
            high: 0xf1f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf34 as libc::c_int as libc::c_ushort,
            high: 0xf34 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf36 as libc::c_int as libc::c_ushort,
            high: 0xf36 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf38 as libc::c_int as libc::c_ushort,
            high: 0xf38 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfbe as libc::c_int as libc::c_ushort,
            high: 0xfc5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfc7 as libc::c_int as libc::c_ushort,
            high: 0xfcc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfcf as libc::c_int as libc::c_ushort,
            high: 0xfcf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17db as libc::c_int as libc::c_ushort,
            high: 0x17db as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1940 as libc::c_int as libc::c_ushort,
            high: 0x1940 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x19e0 as libc::c_int as libc::c_ushort,
            high: 0x19ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbd as libc::c_int as libc::c_ushort,
            high: 0x1fbd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbf as libc::c_int as libc::c_ushort,
            high: 0x1fc1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fcd as libc::c_int as libc::c_ushort,
            high: 0x1fcf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fdd as libc::c_int as libc::c_ushort,
            high: 0x1fdf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fed as libc::c_int as libc::c_ushort,
            high: 0x1fef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ffd as libc::c_int as libc::c_ushort,
            high: 0x1ffe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2044 as libc::c_int as libc::c_ushort,
            high: 0x2044 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2052 as libc::c_int as libc::c_ushort,
            high: 0x2052 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207a as libc::c_int as libc::c_ushort,
            high: 0x207c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208a as libc::c_int as libc::c_ushort,
            high: 0x208c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20a0 as libc::c_int as libc::c_ushort,
            high: 0x20b1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2100 as libc::c_int as libc::c_ushort,
            high: 0x2101 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2103 as libc::c_int as libc::c_ushort,
            high: 0x2106 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2108 as libc::c_int as libc::c_ushort,
            high: 0x2109 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2114 as libc::c_int as libc::c_ushort,
            high: 0x2114 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2116 as libc::c_int as libc::c_ushort,
            high: 0x2118 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x211e as libc::c_int as libc::c_ushort,
            high: 0x2123 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2125 as libc::c_int as libc::c_ushort,
            high: 0x2125 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2127 as libc::c_int as libc::c_ushort,
            high: 0x2127 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2129 as libc::c_int as libc::c_ushort,
            high: 0x2129 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212e as libc::c_int as libc::c_ushort,
            high: 0x212e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2132 as libc::c_int as libc::c_ushort,
            high: 0x2132 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213a as libc::c_int as libc::c_ushort,
            high: 0x213b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2140 as libc::c_int as libc::c_ushort,
            high: 0x2144 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x214a as libc::c_int as libc::c_ushort,
            high: 0x214b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2190 as libc::c_int as libc::c_ushort,
            high: 0x2328 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x232b as libc::c_int as libc::c_ushort,
            high: 0x23b3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b7 as libc::c_int as libc::c_ushort,
            high: 0x23d0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2400 as libc::c_int as libc::c_ushort,
            high: 0x2426 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2440 as libc::c_int as libc::c_ushort,
            high: 0x244a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x249c as libc::c_int as libc::c_ushort,
            high: 0x24e9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2500 as libc::c_int as libc::c_ushort,
            high: 0x2617 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2619 as libc::c_int as libc::c_ushort,
            high: 0x267d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2680 as libc::c_int as libc::c_ushort,
            high: 0x2691 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x26a0 as libc::c_int as libc::c_ushort,
            high: 0x26a1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2701 as libc::c_int as libc::c_ushort,
            high: 0x2704 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2706 as libc::c_int as libc::c_ushort,
            high: 0x2709 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x270c as libc::c_int as libc::c_ushort,
            high: 0x2727 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2729 as libc::c_int as libc::c_ushort,
            high: 0x274b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x274d as libc::c_int as libc::c_ushort,
            high: 0x274d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x274f as libc::c_int as libc::c_ushort,
            high: 0x2752 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2756 as libc::c_int as libc::c_ushort,
            high: 0x2756 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2758 as libc::c_int as libc::c_ushort,
            high: 0x275e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2761 as libc::c_int as libc::c_ushort,
            high: 0x2767 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2794 as libc::c_int as libc::c_ushort,
            high: 0x2794 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2798 as libc::c_int as libc::c_ushort,
            high: 0x27af as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27b1 as libc::c_int as libc::c_ushort,
            high: 0x27be as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27d0 as libc::c_int as libc::c_ushort,
            high: 0x27e5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27f0 as libc::c_int as libc::c_ushort,
            high: 0x2982 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2999 as libc::c_int as libc::c_ushort,
            high: 0x29d7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29dc as libc::c_int as libc::c_ushort,
            high: 0x29fb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29fe as libc::c_int as libc::c_ushort,
            high: 0x2b0d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e80 as libc::c_int as libc::c_ushort,
            high: 0x2e99 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e9b as libc::c_int as libc::c_ushort,
            high: 0x2ef3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2f00 as libc::c_int as libc::c_ushort,
            high: 0x2fd5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ff0 as libc::c_int as libc::c_ushort,
            high: 0x2ffb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3004 as libc::c_int as libc::c_ushort,
            high: 0x3004 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3012 as libc::c_int as libc::c_ushort,
            high: 0x3013 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3020 as libc::c_int as libc::c_ushort,
            high: 0x3020 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3036 as libc::c_int as libc::c_ushort,
            high: 0x3037 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303e as libc::c_int as libc::c_ushort,
            high: 0x303f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309b as libc::c_int as libc::c_ushort,
            high: 0x309c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3190 as libc::c_int as libc::c_ushort,
            high: 0x3191 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3196 as libc::c_int as libc::c_ushort,
            high: 0x319f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3200 as libc::c_int as libc::c_ushort,
            high: 0x321e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x322a as libc::c_int as libc::c_ushort,
            high: 0x3243 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3250 as libc::c_int as libc::c_ushort,
            high: 0x3250 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3260 as libc::c_int as libc::c_ushort,
            high: 0x327d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x327f as libc::c_int as libc::c_ushort,
            high: 0x327f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x328a as libc::c_int as libc::c_ushort,
            high: 0x32b0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x32c0 as libc::c_int as libc::c_ushort,
            high: 0x32fe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3300 as libc::c_int as libc::c_ushort,
            high: 0x33ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4dc0 as libc::c_int as libc::c_ushort,
            high: 0x4dff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa490 as libc::c_int as libc::c_ushort,
            high: 0xa4c6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb29 as libc::c_int as libc::c_ushort,
            high: 0xfb29 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfdfc as libc::c_int as libc::c_ushort,
            high: 0xfdfd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe62 as libc::c_int as libc::c_ushort,
            high: 0xfe62 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe64 as libc::c_int as libc::c_ushort,
            high: 0xfe66 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe69 as libc::c_int as libc::c_ushort,
            high: 0xfe69 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff04 as libc::c_int as libc::c_ushort,
            high: 0xff04 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0b as libc::c_int as libc::c_ushort,
            high: 0xff0b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1c as libc::c_int as libc::c_ushort,
            high: 0xff1e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3e as libc::c_int as libc::c_ushort,
            high: 0xff3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff40 as libc::c_int as libc::c_ushort,
            high: 0xff40 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5c as libc::c_int as libc::c_ushort,
            high: 0xff5c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5e as libc::c_int as libc::c_ushort,
            high: 0xff5e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe0 as libc::c_int as libc::c_ushort,
            high: 0xffe6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe8 as libc::c_int as libc::c_ushort,
            high: 0xffee as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfffc as libc::c_int as libc::c_ushort,
            high: 0xfffd as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlSL: [xmlChLRange; 20] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10102 as libc::c_int as libc::c_uint,
            high: 0x10102 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10137 as libc::c_int as libc::c_uint,
            high: 0x1013f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d000 as libc::c_int as libc::c_uint,
            high: 0x1d0f5 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d100 as libc::c_int as libc::c_uint,
            high: 0x1d126 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d12a as libc::c_int as libc::c_uint,
            high: 0x1d164 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d16a as libc::c_int as libc::c_uint,
            high: 0x1d16c as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d183 as libc::c_int as libc::c_uint,
            high: 0x1d184 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d18c as libc::c_int as libc::c_uint,
            high: 0x1d1a9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d1ae as libc::c_int as libc::c_uint,
            high: 0x1d1dd as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d300 as libc::c_int as libc::c_uint,
            high: 0x1d356 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6c1 as libc::c_int as libc::c_uint,
            high: 0x1d6c1 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6db as libc::c_int as libc::c_uint,
            high: 0x1d6db as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6fb as libc::c_int as libc::c_uint,
            high: 0x1d6fb as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d715 as libc::c_int as libc::c_uint,
            high: 0x1d715 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d735 as libc::c_int as libc::c_uint,
            high: 0x1d735 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d74f as libc::c_int as libc::c_uint,
            high: 0x1d74f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d76f as libc::c_int as libc::c_uint,
            high: 0x1d76f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d789 as libc::c_int as libc::c_uint,
            high: 0x1d789 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7a9 as libc::c_int as libc::c_uint,
            high: 0x1d7a9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7c3 as libc::c_int as libc::c_uint,
            high: 0x1d7c3 as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlSG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 133 as libc::c_int,
            nbLongRange: 20 as libc::c_int,
            shortRange: xmlSS.as_ptr(),
            longRange: xmlSL.as_ptr(),
        };
        init
    }
};
static mut xmlScS: [xmlChSRange; 13] = [
    {
        let mut init = _xmlChSRange {
            low: 0x24 as libc::c_int as libc::c_ushort,
            high: 0x24 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa2 as libc::c_int as libc::c_ushort,
            high: 0xa5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9f2 as libc::c_int as libc::c_ushort,
            high: 0x9f3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaf1 as libc::c_int as libc::c_ushort,
            high: 0xaf1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf9 as libc::c_int as libc::c_ushort,
            high: 0xbf9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe3f as libc::c_int as libc::c_ushort,
            high: 0xe3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x17db as libc::c_int as libc::c_ushort,
            high: 0x17db as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x20a0 as libc::c_int as libc::c_ushort,
            high: 0x20b1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfdfc as libc::c_int as libc::c_ushort,
            high: 0xfdfc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe69 as libc::c_int as libc::c_ushort,
            high: 0xfe69 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff04 as libc::c_int as libc::c_ushort,
            high: 0xff04 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe0 as libc::c_int as libc::c_ushort,
            high: 0xffe1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe5 as libc::c_int as libc::c_ushort,
            high: 0xffe6 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlScG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 13 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlScS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlSkS: [xmlChSRange; 22] = [
    {
        let mut init = _xmlChSRange {
            low: 0x5e as libc::c_int as libc::c_ushort,
            high: 0x5e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60 as libc::c_int as libc::c_ushort,
            high: 0x60 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa8 as libc::c_int as libc::c_ushort,
            high: 0xa8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xaf as libc::c_int as libc::c_ushort,
            high: 0xaf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb4 as libc::c_int as libc::c_ushort,
            high: 0xb4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb8 as libc::c_int as libc::c_ushort,
            high: 0xb8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2c2 as libc::c_int as libc::c_ushort,
            high: 0x2c5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2d2 as libc::c_int as libc::c_ushort,
            high: 0x2df as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e5 as libc::c_int as libc::c_ushort,
            high: 0x2ed as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ef as libc::c_int as libc::c_ushort,
            high: 0x2ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x374 as libc::c_int as libc::c_ushort,
            high: 0x375 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x384 as libc::c_int as libc::c_ushort,
            high: 0x385 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbd as libc::c_int as libc::c_ushort,
            high: 0x1fbd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fbf as libc::c_int as libc::c_ushort,
            high: 0x1fc1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fcd as libc::c_int as libc::c_ushort,
            high: 0x1fcf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fdd as libc::c_int as libc::c_ushort,
            high: 0x1fdf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fed as libc::c_int as libc::c_ushort,
            high: 0x1fef as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1ffd as libc::c_int as libc::c_ushort,
            high: 0x1ffe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309b as libc::c_int as libc::c_ushort,
            high: 0x309c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff3e as libc::c_int as libc::c_ushort,
            high: 0xff3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff40 as libc::c_int as libc::c_ushort,
            high: 0xff40 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe3 as libc::c_int as libc::c_ushort,
            high: 0xffe3 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlSkG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 22 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlSkS.as_ptr(),
            longRange: 0 as *const xmlChLRange,
        };
        init
    }
};
static mut xmlSmS: [xmlChSRange; 48] = [
    {
        let mut init = _xmlChSRange {
            low: 0x2b as libc::c_int as libc::c_ushort,
            high: 0x2b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3c as libc::c_int as libc::c_ushort,
            high: 0x3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7c as libc::c_int as libc::c_ushort,
            high: 0x7c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x7e as libc::c_int as libc::c_ushort,
            high: 0x7e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac as libc::c_int as libc::c_ushort,
            high: 0xac as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb1 as libc::c_int as libc::c_ushort,
            high: 0xb1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xd7 as libc::c_int as libc::c_ushort,
            high: 0xd7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf7 as libc::c_int as libc::c_ushort,
            high: 0xf7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3f6 as libc::c_int as libc::c_ushort,
            high: 0x3f6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2044 as libc::c_int as libc::c_ushort,
            high: 0x2044 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2052 as libc::c_int as libc::c_ushort,
            high: 0x2052 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x207a as libc::c_int as libc::c_ushort,
            high: 0x207c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x208a as libc::c_int as libc::c_ushort,
            high: 0x208c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2140 as libc::c_int as libc::c_ushort,
            high: 0x2144 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x214b as libc::c_int as libc::c_ushort,
            high: 0x214b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2190 as libc::c_int as libc::c_ushort,
            high: 0x2194 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x219a as libc::c_int as libc::c_ushort,
            high: 0x219b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a0 as libc::c_int as libc::c_ushort,
            high: 0x21a0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a3 as libc::c_int as libc::c_ushort,
            high: 0x21a3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a6 as libc::c_int as libc::c_ushort,
            high: 0x21a6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21ae as libc::c_int as libc::c_ushort,
            high: 0x21ae as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21ce as libc::c_int as libc::c_ushort,
            high: 0x21cf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d2 as libc::c_int as libc::c_ushort,
            high: 0x21d2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d4 as libc::c_int as libc::c_ushort,
            high: 0x21d4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21f4 as libc::c_int as libc::c_ushort,
            high: 0x22ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2308 as libc::c_int as libc::c_ushort,
            high: 0x230b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2320 as libc::c_int as libc::c_ushort,
            high: 0x2321 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x237c as libc::c_int as libc::c_ushort,
            high: 0x237c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x239b as libc::c_int as libc::c_ushort,
            high: 0x23b3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25b7 as libc::c_int as libc::c_ushort,
            high: 0x25b7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25c1 as libc::c_int as libc::c_ushort,
            high: 0x25c1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25f8 as libc::c_int as libc::c_ushort,
            high: 0x25ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x266f as libc::c_int as libc::c_ushort,
            high: 0x266f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27d0 as libc::c_int as libc::c_ushort,
            high: 0x27e5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27f0 as libc::c_int as libc::c_ushort,
            high: 0x27ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2900 as libc::c_int as libc::c_ushort,
            high: 0x2982 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2999 as libc::c_int as libc::c_ushort,
            high: 0x29d7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29dc as libc::c_int as libc::c_ushort,
            high: 0x29fb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x29fe as libc::c_int as libc::c_ushort,
            high: 0x2aff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb29 as libc::c_int as libc::c_ushort,
            high: 0xfb29 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe62 as libc::c_int as libc::c_ushort,
            high: 0xfe62 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfe64 as libc::c_int as libc::c_ushort,
            high: 0xfe66 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff0b as libc::c_int as libc::c_ushort,
            high: 0xff0b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff1c as libc::c_int as libc::c_ushort,
            high: 0xff1e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5c as libc::c_int as libc::c_ushort,
            high: 0xff5c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xff5e as libc::c_int as libc::c_ushort,
            high: 0xff5e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe2 as libc::c_int as libc::c_ushort,
            high: 0xffe2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe9 as libc::c_int as libc::c_ushort,
            high: 0xffec as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlSmL: [xmlChLRange; 10] = [
    {
        let mut init = _xmlChLRange {
            low: 0x1d6c1 as libc::c_int as libc::c_uint,
            high: 0x1d6c1 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6db as libc::c_int as libc::c_uint,
            high: 0x1d6db as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d6fb as libc::c_int as libc::c_uint,
            high: 0x1d6fb as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d715 as libc::c_int as libc::c_uint,
            high: 0x1d715 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d735 as libc::c_int as libc::c_uint,
            high: 0x1d735 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d74f as libc::c_int as libc::c_uint,
            high: 0x1d74f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d76f as libc::c_int as libc::c_uint,
            high: 0x1d76f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d789 as libc::c_int as libc::c_uint,
            high: 0x1d789 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7a9 as libc::c_int as libc::c_uint,
            high: 0x1d7a9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d7c3 as libc::c_int as libc::c_uint,
            high: 0x1d7c3 as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlSmG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 48 as libc::c_int,
            nbLongRange: 10 as libc::c_int,
            shortRange: xmlSmS.as_ptr(),
            longRange: xmlSmL.as_ptr(),
        };
        init
    }
};
static mut xmlSoS: [xmlChSRange; 103] = [
    {
        let mut init = _xmlChSRange {
            low: 0xa6 as libc::c_int as libc::c_ushort,
            high: 0xa7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa9 as libc::c_int as libc::c_ushort,
            high: 0xa9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xae as libc::c_int as libc::c_ushort,
            high: 0xae as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb0 as libc::c_int as libc::c_ushort,
            high: 0xb0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb6 as libc::c_int as libc::c_ushort,
            high: 0xb6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x482 as libc::c_int as libc::c_ushort,
            high: 0x482 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x60e as libc::c_int as libc::c_ushort,
            high: 0x60f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e9 as libc::c_int as libc::c_ushort,
            high: 0x6e9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6fd as libc::c_int as libc::c_ushort,
            high: 0x6fe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9fa as libc::c_int as libc::c_ushort,
            high: 0x9fa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xb70 as libc::c_int as libc::c_ushort,
            high: 0xb70 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbf3 as libc::c_int as libc::c_ushort,
            high: 0xbf8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xbfa as libc::c_int as libc::c_ushort,
            high: 0xbfa as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf01 as libc::c_int as libc::c_ushort,
            high: 0xf03 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf13 as libc::c_int as libc::c_ushort,
            high: 0xf17 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf1a as libc::c_int as libc::c_ushort,
            high: 0xf1f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf34 as libc::c_int as libc::c_ushort,
            high: 0xf34 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf36 as libc::c_int as libc::c_ushort,
            high: 0xf36 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf38 as libc::c_int as libc::c_ushort,
            high: 0xf38 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfbe as libc::c_int as libc::c_ushort,
            high: 0xfc5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfc7 as libc::c_int as libc::c_ushort,
            high: 0xfcc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfcf as libc::c_int as libc::c_ushort,
            high: 0xfcf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1940 as libc::c_int as libc::c_ushort,
            high: 0x1940 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x19e0 as libc::c_int as libc::c_ushort,
            high: 0x19ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2100 as libc::c_int as libc::c_ushort,
            high: 0x2101 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2103 as libc::c_int as libc::c_ushort,
            high: 0x2106 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2108 as libc::c_int as libc::c_ushort,
            high: 0x2109 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2114 as libc::c_int as libc::c_ushort,
            high: 0x2114 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2116 as libc::c_int as libc::c_ushort,
            high: 0x2118 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x211e as libc::c_int as libc::c_ushort,
            high: 0x2123 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2125 as libc::c_int as libc::c_ushort,
            high: 0x2125 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2127 as libc::c_int as libc::c_ushort,
            high: 0x2127 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2129 as libc::c_int as libc::c_ushort,
            high: 0x2129 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212e as libc::c_int as libc::c_ushort,
            high: 0x212e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2132 as libc::c_int as libc::c_ushort,
            high: 0x2132 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x213a as libc::c_int as libc::c_ushort,
            high: 0x213b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x214a as libc::c_int as libc::c_ushort,
            high: 0x214a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2195 as libc::c_int as libc::c_ushort,
            high: 0x2199 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x219c as libc::c_int as libc::c_ushort,
            high: 0x219f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a1 as libc::c_int as libc::c_ushort,
            high: 0x21a2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a4 as libc::c_int as libc::c_ushort,
            high: 0x21a5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21a7 as libc::c_int as libc::c_ushort,
            high: 0x21ad as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21af as libc::c_int as libc::c_ushort,
            high: 0x21cd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d0 as libc::c_int as libc::c_ushort,
            high: 0x21d1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d3 as libc::c_int as libc::c_ushort,
            high: 0x21d3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x21d5 as libc::c_int as libc::c_ushort,
            high: 0x21f3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2300 as libc::c_int as libc::c_ushort,
            high: 0x2307 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x230c as libc::c_int as libc::c_ushort,
            high: 0x231f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2322 as libc::c_int as libc::c_ushort,
            high: 0x2328 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x232b as libc::c_int as libc::c_ushort,
            high: 0x237b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x237d as libc::c_int as libc::c_ushort,
            high: 0x239a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x23b7 as libc::c_int as libc::c_ushort,
            high: 0x23d0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2400 as libc::c_int as libc::c_ushort,
            high: 0x2426 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2440 as libc::c_int as libc::c_ushort,
            high: 0x244a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x249c as libc::c_int as libc::c_ushort,
            high: 0x24e9 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2500 as libc::c_int as libc::c_ushort,
            high: 0x25b6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25b8 as libc::c_int as libc::c_ushort,
            high: 0x25c0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x25c2 as libc::c_int as libc::c_ushort,
            high: 0x25f7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2600 as libc::c_int as libc::c_ushort,
            high: 0x2617 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2619 as libc::c_int as libc::c_ushort,
            high: 0x266e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2670 as libc::c_int as libc::c_ushort,
            high: 0x267d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2680 as libc::c_int as libc::c_ushort,
            high: 0x2691 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x26a0 as libc::c_int as libc::c_ushort,
            high: 0x26a1 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2701 as libc::c_int as libc::c_ushort,
            high: 0x2704 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2706 as libc::c_int as libc::c_ushort,
            high: 0x2709 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x270c as libc::c_int as libc::c_ushort,
            high: 0x2727 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2729 as libc::c_int as libc::c_ushort,
            high: 0x274b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x274d as libc::c_int as libc::c_ushort,
            high: 0x274d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x274f as libc::c_int as libc::c_ushort,
            high: 0x2752 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2756 as libc::c_int as libc::c_ushort,
            high: 0x2756 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2758 as libc::c_int as libc::c_ushort,
            high: 0x275e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2761 as libc::c_int as libc::c_ushort,
            high: 0x2767 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2794 as libc::c_int as libc::c_ushort,
            high: 0x2794 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2798 as libc::c_int as libc::c_ushort,
            high: 0x27af as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x27b1 as libc::c_int as libc::c_ushort,
            high: 0x27be as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2800 as libc::c_int as libc::c_ushort,
            high: 0x28ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2b00 as libc::c_int as libc::c_ushort,
            high: 0x2b0d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e80 as libc::c_int as libc::c_ushort,
            high: 0x2e99 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2e9b as libc::c_int as libc::c_ushort,
            high: 0x2ef3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2f00 as libc::c_int as libc::c_ushort,
            high: 0x2fd5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2ff0 as libc::c_int as libc::c_ushort,
            high: 0x2ffb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3004 as libc::c_int as libc::c_ushort,
            high: 0x3004 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3012 as libc::c_int as libc::c_ushort,
            high: 0x3013 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3020 as libc::c_int as libc::c_ushort,
            high: 0x3020 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3036 as libc::c_int as libc::c_ushort,
            high: 0x3037 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x303e as libc::c_int as libc::c_ushort,
            high: 0x303f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3190 as libc::c_int as libc::c_ushort,
            high: 0x3191 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3196 as libc::c_int as libc::c_ushort,
            high: 0x319f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3200 as libc::c_int as libc::c_ushort,
            high: 0x321e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x322a as libc::c_int as libc::c_ushort,
            high: 0x3243 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3250 as libc::c_int as libc::c_ushort,
            high: 0x3250 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3260 as libc::c_int as libc::c_ushort,
            high: 0x327d as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x327f as libc::c_int as libc::c_ushort,
            high: 0x327f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x328a as libc::c_int as libc::c_ushort,
            high: 0x32b0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x32c0 as libc::c_int as libc::c_ushort,
            high: 0x32fe as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3300 as libc::c_int as libc::c_ushort,
            high: 0x33ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4dc0 as libc::c_int as libc::c_ushort,
            high: 0x4dff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa490 as libc::c_int as libc::c_ushort,
            high: 0xa4c6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfdfd as libc::c_int as libc::c_ushort,
            high: 0xfdfd as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe4 as libc::c_int as libc::c_ushort,
            high: 0xffe4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffe8 as libc::c_int as libc::c_ushort,
            high: 0xffe8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xffed as libc::c_int as libc::c_ushort,
            high: 0xffee as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfffc as libc::c_int as libc::c_ushort,
            high: 0xfffd as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlSoL: [xmlChLRange; 10] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10102 as libc::c_int as libc::c_uint,
            high: 0x10102 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x10137 as libc::c_int as libc::c_uint,
            high: 0x1013f as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d000 as libc::c_int as libc::c_uint,
            high: 0x1d0f5 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d100 as libc::c_int as libc::c_uint,
            high: 0x1d126 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d12a as libc::c_int as libc::c_uint,
            high: 0x1d164 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d16a as libc::c_int as libc::c_uint,
            high: 0x1d16c as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d183 as libc::c_int as libc::c_uint,
            high: 0x1d184 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d18c as libc::c_int as libc::c_uint,
            high: 0x1d1a9 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d1ae as libc::c_int as libc::c_uint,
            high: 0x1d1dd as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = _xmlChLRange {
            low: 0x1d300 as libc::c_int as libc::c_uint,
            high: 0x1d356 as libc::c_int as libc::c_uint,
        };
        init
    },
];
static mut xmlSoG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 103 as libc::c_int,
            nbLongRange: 10 as libc::c_int,
            shortRange: xmlSoS.as_ptr(),
            longRange: xmlSoL.as_ptr(),
        };
        init
    }
};
static mut xmlZS: [xmlChSRange; 9] = [
    {
        let mut init = _xmlChSRange {
            low: 0x20 as libc::c_int as libc::c_ushort,
            high: 0x20 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa0 as libc::c_int as libc::c_ushort,
            high: 0xa0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1680 as libc::c_int as libc::c_ushort,
            high: 0x1680 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x180e as libc::c_int as libc::c_ushort,
            high: 0x180e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2000 as libc::c_int as libc::c_ushort,
            high: 0x200a as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2028 as libc::c_int as libc::c_ushort,
            high: 0x2029 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x202f as libc::c_int as libc::c_ushort,
            high: 0x202f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x205f as libc::c_int as libc::c_ushort,
            high: 0x205f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3000 as libc::c_int as libc::c_ushort,
            high: 0x3000 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlZG: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 9 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
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
            numentries: 128 as libc::c_int,
        };
        init
    }
};
static mut xmlUnicodeCatTbl: xmlUnicodeNameTable = unsafe {
    {
        let mut init = xmlUnicodeNameTable {
            table: xmlUnicodeCats.as_ptr(),
            numentries: 36 as libc::c_int,
        };
        init
    }
};
unsafe extern "C" fn xmlUnicodeLookup(
    mut tptr: *const xmlUnicodeNameTable,
    mut tname: *const libc::c_char,
) -> Option::<xmlIntFunc> {
    let mut low: libc::c_int = 0;
    let mut high: libc::c_int = 0;
    let mut mid: libc::c_int = 0;
    let mut cmp: libc::c_int = 0;
    let mut sptr: *const xmlUnicodeRange = 0 as *const xmlUnicodeRange;
    if tptr.is_null() || tname.is_null() {
        return None;
    }
    low = 0 as libc::c_int;
    high = (*tptr).numentries - 1 as libc::c_int;
    sptr = (*tptr).table;
    while low <= high {
        mid = (low + high) / 2 as libc::c_int;
        cmp = strcmp(tname, (*sptr.offset(mid as isize)).rangename);
        if cmp == 0 as libc::c_int {
            return (*sptr.offset(mid as isize)).func;
        }
        if cmp < 0 as libc::c_int {
            high = mid - 1 as libc::c_int;
        } else {
            low = mid + 1 as libc::c_int;
        }
    }
    return None;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsAegeanNumbers(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10100 as libc::c_int && code <= 0x1013f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsAlphabeticPresentationForms(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xfb00 as libc::c_int && code <= 0xfb4f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsArabic(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x600 as libc::c_int && code <= 0x6ff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsArabicPresentationFormsA(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xfb50 as libc::c_int && code <= 0xfdff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsArabicPresentationFormsB(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xfe70 as libc::c_int && code <= 0xfeff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsArmenian(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x530 as libc::c_int && code <= 0x58f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsArrows(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x2190 as libc::c_int && code <= 0x21ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsBasicLatin(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0 as libc::c_int && code <= 0x7f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsBengali(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x980 as libc::c_int && code <= 0x9ff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsBlockElements(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x2580 as libc::c_int && code <= 0x259f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsBopomofo(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x3100 as libc::c_int && code <= 0x312f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsBopomofoExtended(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x31a0 as libc::c_int && code <= 0x31bf as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsBoxDrawing(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x2500 as libc::c_int && code <= 0x257f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsBraillePatterns(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x2800 as libc::c_int && code <= 0x28ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsBuhid(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1740 as libc::c_int && code <= 0x175f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsByzantineMusicalSymbols(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x1d000 as libc::c_int && code <= 0x1d0ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCJKCompatibility(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x3300 as libc::c_int && code <= 0x33ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCJKCompatibilityForms(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xfe30 as libc::c_int && code <= 0xfe4f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCJKCompatibilityIdeographs(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xf900 as libc::c_int && code <= 0xfaff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCJKCompatibilityIdeographsSupplement(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2f800 as libc::c_int && code <= 0x2fa1f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCJKRadicalsSupplement(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2e80 as libc::c_int && code <= 0x2eff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCJKSymbolsandPunctuation(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x3000 as libc::c_int && code <= 0x303f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCJKUnifiedIdeographs(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x4e00 as libc::c_int && code <= 0x9fff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCJKUnifiedIdeographsExtensionA(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x3400 as libc::c_int && code <= 0x4dbf as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCJKUnifiedIdeographsExtensionB(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x20000 as libc::c_int && code <= 0x2a6df as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCherokee(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x13a0 as libc::c_int && code <= 0x13ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCombiningDiacriticalMarks(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x300 as libc::c_int && code <= 0x36f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCombiningDiacriticalMarksforSymbols(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x20d0 as libc::c_int && code <= 0x20ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCombiningHalfMarks(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xfe20 as libc::c_int && code <= 0xfe2f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCombiningMarksforSymbols(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x20d0 as libc::c_int && code <= 0x20ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsControlPictures(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x2400 as libc::c_int && code <= 0x243f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCurrencySymbols(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x20a0 as libc::c_int && code <= 0x20cf as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCypriotSyllabary(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10800 as libc::c_int && code <= 0x1083f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCyrillic(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x400 as libc::c_int && code <= 0x4ff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCyrillicSupplement(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x500 as libc::c_int && code <= 0x52f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsDeseret(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10400 as libc::c_int && code <= 0x1044f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsDevanagari(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x900 as libc::c_int && code <= 0x97f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsDingbats(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x2700 as libc::c_int && code <= 0x27bf as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsEnclosedAlphanumerics(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2460 as libc::c_int && code <= 0x24ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsEnclosedCJKLettersandMonths(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x3200 as libc::c_int && code <= 0x32ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsEthiopic(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1200 as libc::c_int && code <= 0x137f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsGeneralPunctuation(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2000 as libc::c_int && code <= 0x206f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsGeometricShapes(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x25a0 as libc::c_int && code <= 0x25ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsGeorgian(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10a0 as libc::c_int && code <= 0x10ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsGothic(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10330 as libc::c_int && code <= 0x1034f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsGreek(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x370 as libc::c_int && code <= 0x3ff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsGreekExtended(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1f00 as libc::c_int && code <= 0x1fff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsGreekandCoptic(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x370 as libc::c_int && code <= 0x3ff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsGujarati(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xa80 as libc::c_int && code <= 0xaff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsGurmukhi(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xa00 as libc::c_int && code <= 0xa7f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsHalfwidthandFullwidthForms(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xff00 as libc::c_int && code <= 0xffef as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsHangulCompatibilityJamo(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x3130 as libc::c_int && code <= 0x318f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsHangulJamo(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1100 as libc::c_int && code <= 0x11ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsHangulSyllables(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xac00 as libc::c_int && code <= 0xd7af as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsHanunoo(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1720 as libc::c_int && code <= 0x173f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsHebrew(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x590 as libc::c_int && code <= 0x5ff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsHighPrivateUseSurrogates(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xdb80 as libc::c_int && code <= 0xdbff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsHighSurrogates(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xd800 as libc::c_int && code <= 0xdb7f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsHiragana(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x3040 as libc::c_int && code <= 0x309f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsIPAExtensions(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x250 as libc::c_int && code <= 0x2af as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsIdeographicDescriptionCharacters(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2ff0 as libc::c_int && code <= 0x2fff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsKanbun(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x3190 as libc::c_int && code <= 0x319f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsKangxiRadicals(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x2f00 as libc::c_int && code <= 0x2fdf as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsKannada(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xc80 as libc::c_int && code <= 0xcff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsKatakana(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x30a0 as libc::c_int && code <= 0x30ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsKatakanaPhoneticExtensions(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x31f0 as libc::c_int && code <= 0x31ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsKhmer(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1780 as libc::c_int && code <= 0x17ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsKhmerSymbols(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x19e0 as libc::c_int && code <= 0x19ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsLao(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xe80 as libc::c_int && code <= 0xeff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsLatin1Supplement(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x80 as libc::c_int && code <= 0xff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsLatinExtendedA(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x100 as libc::c_int && code <= 0x17f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsLatinExtendedB(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x180 as libc::c_int && code <= 0x24f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsLatinExtendedAdditional(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x1e00 as libc::c_int && code <= 0x1eff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsLetterlikeSymbols(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2100 as libc::c_int && code <= 0x214f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsLimbu(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1900 as libc::c_int && code <= 0x194f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsLinearBIdeograms(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10080 as libc::c_int && code <= 0x100ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsLinearBSyllabary(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10000 as libc::c_int && code <= 0x1007f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsLowSurrogates(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xdc00 as libc::c_int && code <= 0xdfff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMalayalam(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xd00 as libc::c_int && code <= 0xd7f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMathematicalAlphanumericSymbols(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x1d400 as libc::c_int && code <= 0x1d7ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMathematicalOperators(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2200 as libc::c_int && code <= 0x22ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMiscellaneousMathematicalSymbolsA(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x27c0 as libc::c_int && code <= 0x27ef as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMiscellaneousMathematicalSymbolsB(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2980 as libc::c_int && code <= 0x29ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMiscellaneousSymbols(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2600 as libc::c_int && code <= 0x26ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMiscellaneousSymbolsandArrows(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2b00 as libc::c_int && code <= 0x2bff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMiscellaneousTechnical(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2300 as libc::c_int && code <= 0x23ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMongolian(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1800 as libc::c_int && code <= 0x18af as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMusicalSymbols(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1d100 as libc::c_int && code <= 0x1d1ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsMyanmar(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1000 as libc::c_int && code <= 0x109f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsNumberForms(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x2150 as libc::c_int && code <= 0x218f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsOgham(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1680 as libc::c_int && code <= 0x169f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsOldItalic(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10300 as libc::c_int && code <= 0x1032f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsOpticalCharacterRecognition(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2440 as libc::c_int && code <= 0x245f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsOriya(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xb00 as libc::c_int && code <= 0xb7f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsOsmanya(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10480 as libc::c_int && code <= 0x104af as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsPhoneticExtensions(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x1d00 as libc::c_int && code <= 0x1d7f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsPrivateUse(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xe000 as libc::c_int && code <= 0xf8ff as libc::c_int
        || code >= 0xf0000 as libc::c_int && code <= 0xfffff as libc::c_int
        || code >= 0x100000 as libc::c_int && code <= 0x10ffff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsPrivateUseArea(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xe000 as libc::c_int && code <= 0xf8ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsRunic(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x16a0 as libc::c_int && code <= 0x16ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsShavian(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10450 as libc::c_int && code <= 0x1047f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSinhala(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xd80 as libc::c_int && code <= 0xdff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSmallFormVariants(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xfe50 as libc::c_int && code <= 0xfe6f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSpacingModifierLetters(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2b0 as libc::c_int && code <= 0x2ff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSpecials(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xfff0 as libc::c_int && code <= 0xffff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSuperscriptsandSubscripts(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2070 as libc::c_int && code <= 0x209f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSupplementalArrowsA(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x27f0 as libc::c_int && code <= 0x27ff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSupplementalArrowsB(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2900 as libc::c_int && code <= 0x297f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSupplementalMathematicalOperators(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x2a00 as libc::c_int && code <= 0x2aff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSupplementaryPrivateUseAreaA(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xf0000 as libc::c_int && code <= 0xfffff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSupplementaryPrivateUseAreaB(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x100000 as libc::c_int && code <= 0x10ffff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsSyriac(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x700 as libc::c_int && code <= 0x74f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsTagalog(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1700 as libc::c_int && code <= 0x171f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsTagbanwa(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1760 as libc::c_int && code <= 0x177f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsTags(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xe0000 as libc::c_int && code <= 0xe007f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsTaiLe(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x1950 as libc::c_int && code <= 0x197f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsTaiXuanJingSymbols(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x1d300 as libc::c_int && code <= 0x1d35f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsTamil(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xb80 as libc::c_int && code <= 0xbff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsTelugu(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xc00 as libc::c_int && code <= 0xc7f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsThaana(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x780 as libc::c_int && code <= 0x7bf as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsThai(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xe00 as libc::c_int && code <= 0xe7f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsTibetan(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xf00 as libc::c_int && code <= 0xfff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsUgaritic(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x10380 as libc::c_int && code <= 0x1039f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsUnifiedCanadianAboriginalSyllabics(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x1400 as libc::c_int && code <= 0x167f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsVariationSelectors(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xfe00 as libc::c_int && code <= 0xfe0f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsVariationSelectorsSupplement(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0xe0100 as libc::c_int && code <= 0xe01ef as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsYiRadicals(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xa490 as libc::c_int && code <= 0xa4cf as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsYiSyllables(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0xa000 as libc::c_int && code <= 0xa48f as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsYijingHexagramSymbols(
    mut code: libc::c_int,
) -> libc::c_int {
    return (code >= 0x4dc0 as libc::c_int && code <= 0x4dff as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsBlock(
    mut code: libc::c_int,
    mut block: *const libc::c_char,
) -> libc::c_int {
    let mut func: Option::<xmlIntFunc> = None;
    func = xmlUnicodeLookup(&xmlUnicodeBlockTbl, block);
    if func.is_none() {
        return -(1 as libc::c_int);
    }
    return func.expect("non-null function pointer")(code);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatC(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlCG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatCc(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0 as libc::c_int && code <= 0x1f as libc::c_int
        || code >= 0x7f as libc::c_int && code <= 0x9f as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatCf(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlCfG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatCo(mut code: libc::c_int) -> libc::c_int {
    return (code == 0xe000 as libc::c_int || code == 0xf8ff as libc::c_int
        || code == 0xf0000 as libc::c_int || code == 0xffffd as libc::c_int
        || code == 0x100000 as libc::c_int || code == 0x10fffd as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatCs(mut code: libc::c_int) -> libc::c_int {
    return (code == 0xd800 as libc::c_int
        || code >= 0xdb7f as libc::c_int && code <= 0xdb80 as libc::c_int
        || code >= 0xdbff as libc::c_int && code <= 0xdc00 as libc::c_int
        || code == 0xdfff as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatL(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlLG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatLl(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlLlG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatLm(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlLmG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatLo(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlLoG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatLt(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlLtG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatLu(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlLuG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatM(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlMG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatMc(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlMcG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatMe(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x488 as libc::c_int && code <= 0x489 as libc::c_int
        || code == 0x6de as libc::c_int
        || code >= 0x20dd as libc::c_int && code <= 0x20e0 as libc::c_int
        || code >= 0x20e2 as libc::c_int && code <= 0x20e4 as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatMn(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlMnG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatN(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlNG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatNd(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlNdG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatNl(mut code: libc::c_int) -> libc::c_int {
    return (code >= 0x16ee as libc::c_int && code <= 0x16f0 as libc::c_int
        || code >= 0x2160 as libc::c_int && code <= 0x2183 as libc::c_int
        || code == 0x3007 as libc::c_int
        || code >= 0x3021 as libc::c_int && code <= 0x3029 as libc::c_int
        || code >= 0x3038 as libc::c_int && code <= 0x303a as libc::c_int
        || code == 0x1034a as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatNo(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlNoG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatP(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlPG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatPc(mut code: libc::c_int) -> libc::c_int {
    return (code == 0x5f as libc::c_int
        || code >= 0x203f as libc::c_int && code <= 0x2040 as libc::c_int
        || code == 0x2054 as libc::c_int || code == 0x30fb as libc::c_int
        || code >= 0xfe33 as libc::c_int && code <= 0xfe34 as libc::c_int
        || code >= 0xfe4d as libc::c_int && code <= 0xfe4f as libc::c_int
        || code == 0xff3f as libc::c_int || code == 0xff65 as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatPd(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlPdG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatPe(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlPeG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatPf(mut code: libc::c_int) -> libc::c_int {
    return (code == 0xbb as libc::c_int || code == 0x2019 as libc::c_int
        || code == 0x201d as libc::c_int || code == 0x203a as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatPi(mut code: libc::c_int) -> libc::c_int {
    return (code == 0xab as libc::c_int || code == 0x2018 as libc::c_int
        || code >= 0x201b as libc::c_int && code <= 0x201c as libc::c_int
        || code == 0x201f as libc::c_int || code == 0x2039 as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatPo(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlPoG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatPs(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlPsG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatS(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlSG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatSc(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlScG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatSk(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlSkG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatSm(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlSmG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatSo(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlSoG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatZ(mut code: libc::c_int) -> libc::c_int {
    return xmlCharInRange(code as libc::c_uint, &xmlZG);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatZl(mut code: libc::c_int) -> libc::c_int {
    return (code == 0x2028 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatZp(mut code: libc::c_int) -> libc::c_int {
    return (code == 0x2029 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCatZs(mut code: libc::c_int) -> libc::c_int {
    return (code == 0x20 as libc::c_int || code == 0xa0 as libc::c_int
        || code == 0x1680 as libc::c_int || code == 0x180e as libc::c_int
        || code >= 0x2000 as libc::c_int && code <= 0x200a as libc::c_int
        || code == 0x202f as libc::c_int || code == 0x205f as libc::c_int
        || code == 0x3000 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUCSIsCat(
    mut code: libc::c_int,
    mut cat: *const libc::c_char,
) -> libc::c_int {
    let mut func: Option::<xmlIntFunc> = None;
    func = xmlUnicodeLookup(&xmlUnicodeCatTbl, cat);
    if func.is_none() {
        return -(1 as libc::c_int);
    }
    return func.expect("non-null function pointer")(code);
}
