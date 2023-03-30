use ::libc;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChSRange;
pub use crate::src::HTMLparser::xmlChSRange;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChLRange;
pub use crate::src::HTMLparser::xmlChLRange;
pub type xmlChLRangePtr = *mut xmlChLRange;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChRangeGroup;
pub use crate::src::HTMLparser::xmlChRangeGroup;
#[no_mangle]
pub static mut xmlIsPubidChar_tab: [libc::c_uchar; 256] = [
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
];
static mut xmlIsBaseChar_srng: [xmlChSRange; 197] = [
    {
        let mut init = _xmlChSRange {
            low: 0x100 as libc::c_int as libc::c_ushort,
            high: 0x131 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x134 as libc::c_int as libc::c_ushort,
            high: 0x13e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x141 as libc::c_int as libc::c_ushort,
            high: 0x148 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x14a as libc::c_int as libc::c_ushort,
            high: 0x17e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x180 as libc::c_int as libc::c_ushort,
            high: 0x1c3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1cd as libc::c_int as libc::c_ushort,
            high: 0x1f0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1f4 as libc::c_int as libc::c_ushort,
            high: 0x1f5 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1fa as libc::c_int as libc::c_ushort,
            high: 0x217 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x250 as libc::c_int as libc::c_ushort,
            high: 0x2a8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2bb as libc::c_int as libc::c_ushort,
            high: 0x2c1 as libc::c_int as libc::c_ushort,
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
            high: 0x3d6 as libc::c_int as libc::c_ushort,
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
            high: 0x3f3 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x401 as libc::c_int as libc::c_ushort,
            high: 0x40c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x40e as libc::c_int as libc::c_ushort,
            high: 0x44f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x451 as libc::c_int as libc::c_ushort,
            high: 0x45c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x45e as libc::c_int as libc::c_ushort,
            high: 0x481 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x490 as libc::c_int as libc::c_ushort,
            high: 0x4c4 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4c7 as libc::c_int as libc::c_ushort,
            high: 0x4c8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4cb as libc::c_int as libc::c_ushort,
            high: 0x4cc as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4d0 as libc::c_int as libc::c_ushort,
            high: 0x4eb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x4ee as libc::c_int as libc::c_ushort,
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
            high: 0x586 as libc::c_int as libc::c_ushort,
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
            low: 0x671 as libc::c_int as libc::c_ushort,
            high: 0x6b7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6ba as libc::c_int as libc::c_ushort,
            high: 0x6be as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6c0 as libc::c_int as libc::c_ushort,
            high: 0x6ce as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6d0 as libc::c_int as libc::c_ushort,
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
            low: 0x905 as libc::c_int as libc::c_ushort,
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
            high: 0xa8b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa8d as libc::c_int as libc::c_ushort,
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
            low: 0xae0 as libc::c_int as libc::c_ushort,
            high: 0xae0 as libc::c_int as libc::c_ushort,
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
            low: 0xb36 as libc::c_int as libc::c_ushort,
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
            low: 0xe01 as libc::c_int as libc::c_ushort,
            high: 0xe2e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe30 as libc::c_int as libc::c_ushort,
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
            high: 0xeae as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xeb0 as libc::c_int as libc::c_ushort,
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
            low: 0xf40 as libc::c_int as libc::c_ushort,
            high: 0xf47 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf49 as libc::c_int as libc::c_ushort,
            high: 0xf69 as libc::c_int as libc::c_ushort,
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
            high: 0x10f6 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1100 as libc::c_int as libc::c_ushort,
            high: 0x1100 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1102 as libc::c_int as libc::c_ushort,
            high: 0x1103 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1105 as libc::c_int as libc::c_ushort,
            high: 0x1107 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1109 as libc::c_int as libc::c_ushort,
            high: 0x1109 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x110b as libc::c_int as libc::c_ushort,
            high: 0x110c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x110e as libc::c_int as libc::c_ushort,
            high: 0x1112 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x113c as libc::c_int as libc::c_ushort,
            high: 0x113c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x113e as libc::c_int as libc::c_ushort,
            high: 0x113e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1140 as libc::c_int as libc::c_ushort,
            high: 0x1140 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x114c as libc::c_int as libc::c_ushort,
            high: 0x114c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x114e as libc::c_int as libc::c_ushort,
            high: 0x114e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1150 as libc::c_int as libc::c_ushort,
            high: 0x1150 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1154 as libc::c_int as libc::c_ushort,
            high: 0x1155 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1159 as libc::c_int as libc::c_ushort,
            high: 0x1159 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x115f as libc::c_int as libc::c_ushort,
            high: 0x1161 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1163 as libc::c_int as libc::c_ushort,
            high: 0x1163 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1165 as libc::c_int as libc::c_ushort,
            high: 0x1165 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1167 as libc::c_int as libc::c_ushort,
            high: 0x1167 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1169 as libc::c_int as libc::c_ushort,
            high: 0x1169 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x116d as libc::c_int as libc::c_ushort,
            high: 0x116e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1172 as libc::c_int as libc::c_ushort,
            high: 0x1173 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x1175 as libc::c_int as libc::c_ushort,
            high: 0x1175 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x119e as libc::c_int as libc::c_ushort,
            high: 0x119e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11a8 as libc::c_int as libc::c_ushort,
            high: 0x11a8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11ab as libc::c_int as libc::c_ushort,
            high: 0x11ab as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11ae as libc::c_int as libc::c_ushort,
            high: 0x11af as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11b7 as libc::c_int as libc::c_ushort,
            high: 0x11b8 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11ba as libc::c_int as libc::c_ushort,
            high: 0x11ba as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11bc as libc::c_int as libc::c_ushort,
            high: 0x11c2 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11eb as libc::c_int as libc::c_ushort,
            high: 0x11eb as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11f0 as libc::c_int as libc::c_ushort,
            high: 0x11f0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x11f9 as libc::c_int as libc::c_ushort,
            high: 0x11f9 as libc::c_int as libc::c_ushort,
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
            low: 0x2126 as libc::c_int as libc::c_ushort,
            high: 0x2126 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x212a as libc::c_int as libc::c_ushort,
            high: 0x212b as libc::c_int as libc::c_ushort,
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
            low: 0x2180 as libc::c_int as libc::c_ushort,
            high: 0x2182 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3041 as libc::c_int as libc::c_ushort,
            high: 0x3094 as libc::c_int as libc::c_ushort,
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
            low: 0x3105 as libc::c_int as libc::c_ushort,
            high: 0x312c as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xac00 as libc::c_int as libc::c_ushort,
            high: 0xd7a3 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
#[no_mangle]
pub static mut xmlIsBaseCharGroup: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 197 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlIsBaseChar_srng.as_ptr(),
            longRange: 0 as *const xmlChLRange as xmlChLRangePtr as *const xmlChLRange,
        };
        init
    }
};
static mut xmlIsChar_srng: [xmlChSRange; 2] = [
    {
        let mut init = _xmlChSRange {
            low: 0x100 as libc::c_int as libc::c_ushort,
            high: 0xd7ff as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xe000 as libc::c_int as libc::c_ushort,
            high: 0xfffd as libc::c_int as libc::c_ushort,
        };
        init
    },
];
static mut xmlIsChar_lrng: [xmlChLRange; 1] = [
    {
        let mut init = _xmlChLRange {
            low: 0x10000 as libc::c_int as libc::c_uint,
            high: 0x10ffff as libc::c_int as libc::c_uint,
        };
        init
    },
];
#[no_mangle]
pub static mut xmlIsCharGroup: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 2 as libc::c_int,
            nbLongRange: 1 as libc::c_int,
            shortRange: xmlIsChar_srng.as_ptr(),
            longRange: xmlIsChar_lrng.as_ptr(),
        };
        init
    }
};
static mut xmlIsCombining_srng: [xmlChSRange; 95] = [
    {
        let mut init = _xmlChSRange {
            low: 0x300 as libc::c_int as libc::c_ushort,
            high: 0x345 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x360 as libc::c_int as libc::c_ushort,
            high: 0x361 as libc::c_int as libc::c_ushort,
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
            low: 0x64b as libc::c_int as libc::c_ushort,
            high: 0x652 as libc::c_int as libc::c_ushort,
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
            low: 0x6dd as libc::c_int as libc::c_ushort,
            high: 0x6df as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x6e0 as libc::c_int as libc::c_ushort,
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
            high: 0x94c as libc::c_int as libc::c_ushort,
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
            high: 0x9be as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9bf as libc::c_int as libc::c_ushort,
            high: 0x9bf as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x9c0 as libc::c_int as libc::c_ushort,
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
            low: 0xa02 as libc::c_int as libc::c_ushort,
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
            low: 0xa3e as libc::c_int as libc::c_ushort,
            high: 0xa3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa3f as libc::c_int as libc::c_ushort,
            high: 0xa3f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xa40 as libc::c_int as libc::c_ushort,
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
            high: 0xb83 as libc::c_int as libc::c_ushort,
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
            high: 0xf3e as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf3f as libc::c_int as libc::c_ushort,
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
            high: 0xf8b as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf90 as libc::c_int as libc::c_ushort,
            high: 0xf95 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf97 as libc::c_int as libc::c_ushort,
            high: 0xf97 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xf99 as libc::c_int as libc::c_ushort,
            high: 0xfad as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb1 as libc::c_int as libc::c_ushort,
            high: 0xfb7 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0xfb9 as libc::c_int as libc::c_ushort,
            high: 0xfb9 as libc::c_int as libc::c_ushort,
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
            low: 0x302a as libc::c_int as libc::c_ushort,
            high: 0x302f as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x3099 as libc::c_int as libc::c_ushort,
            high: 0x3099 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x309a as libc::c_int as libc::c_ushort,
            high: 0x309a as libc::c_int as libc::c_ushort,
        };
        init
    },
];
#[no_mangle]
pub static mut xmlIsCombiningGroup: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 95 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlIsCombining_srng.as_ptr(),
            longRange: 0 as *const xmlChLRange as xmlChLRangePtr as *const xmlChLRange,
        };
        init
    }
};
static mut xmlIsDigit_srng: [xmlChSRange; 14] = [
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
];
#[no_mangle]
pub static mut xmlIsDigitGroup: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 14 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlIsDigit_srng.as_ptr(),
            longRange: 0 as *const xmlChLRange as xmlChLRangePtr as *const xmlChLRange,
        };
        init
    }
};
static mut xmlIsExtender_srng: [xmlChSRange; 10] = [
    {
        let mut init = _xmlChSRange {
            low: 0x2d0 as libc::c_int as libc::c_ushort,
            high: 0x2d0 as libc::c_int as libc::c_ushort,
        };
        init
    },
    {
        let mut init = _xmlChSRange {
            low: 0x2d1 as libc::c_int as libc::c_ushort,
            high: 0x2d1 as libc::c_int as libc::c_ushort,
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
            low: 0x640 as libc::c_int as libc::c_ushort,
            high: 0x640 as libc::c_int as libc::c_ushort,
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
];
#[no_mangle]
pub static mut xmlIsExtenderGroup: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 10 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlIsExtender_srng.as_ptr(),
            longRange: 0 as *const xmlChLRange as xmlChLRangePtr as *const xmlChLRange,
        };
        init
    }
};
static mut xmlIsIdeographic_srng: [xmlChSRange; 3] = [
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
            low: 0x4e00 as libc::c_int as libc::c_ushort,
            high: 0x9fa5 as libc::c_int as libc::c_ushort,
        };
        init
    },
];
#[no_mangle]
pub static mut xmlIsIdeographicGroup: xmlChRangeGroup = unsafe {
    {
        let mut init = _xmlChRangeGroup {
            nbShortRange: 3 as libc::c_int,
            nbLongRange: 0 as libc::c_int,
            shortRange: xmlIsIdeographic_srng.as_ptr(),
            longRange: 0 as *const xmlChLRange as xmlChLRangePtr as *const xmlChLRange,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn xmlCharInRange(
    mut val: libc::c_uint,
    mut rptr: *const xmlChRangeGroup,
) -> libc::c_int {
    let mut low: libc::c_int = 0;
    let mut high: libc::c_int = 0;
    let mut mid: libc::c_int = 0;
    let mut sptr: *const xmlChSRange = 0 as *const xmlChSRange;
    let mut lptr: *const xmlChLRange = 0 as *const xmlChLRange;
    if rptr.is_null() {
        return 0 as libc::c_int;
    }
    if val < 0x10000 as libc::c_int as libc::c_uint {
        if (*rptr).nbShortRange == 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        low = 0 as libc::c_int;
        high = (*rptr).nbShortRange - 1 as libc::c_int;
        sptr = (*rptr).shortRange;
        while low <= high {
            mid = (low + high) / 2 as libc::c_int;
            if (val as libc::c_ushort as libc::c_int)
                < (*sptr.offset(mid as isize)).low as libc::c_int
            {
                high = mid - 1 as libc::c_int;
            } else if val as libc::c_ushort as libc::c_int
                    > (*sptr.offset(mid as isize)).high as libc::c_int
                {
                low = mid + 1 as libc::c_int;
            } else {
                return 1 as libc::c_int
            }
        }
    } else {
        if (*rptr).nbLongRange == 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        low = 0 as libc::c_int;
        high = (*rptr).nbLongRange - 1 as libc::c_int;
        lptr = (*rptr).longRange;
        while low <= high {
            mid = (low + high) / 2 as libc::c_int;
            if val < (*lptr.offset(mid as isize)).low {
                high = mid - 1 as libc::c_int;
            } else if val > (*lptr.offset(mid as isize)).high {
                low = mid + 1 as libc::c_int;
            } else {
                return 1 as libc::c_int
            }
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsBaseChar(mut ch: libc::c_uint) -> libc::c_int {
    return if ch < 0x100 as libc::c_int as libc::c_uint {
        (0x41 as libc::c_int as libc::c_uint <= ch
            && ch <= 0x5a as libc::c_int as libc::c_uint
            || 0x61 as libc::c_int as libc::c_uint <= ch
                && ch <= 0x7a as libc::c_int as libc::c_uint
            || 0xc0 as libc::c_int as libc::c_uint <= ch
                && ch <= 0xd6 as libc::c_int as libc::c_uint
            || 0xd8 as libc::c_int as libc::c_uint <= ch
                && ch <= 0xf6 as libc::c_int as libc::c_uint
            || 0xf8 as libc::c_int as libc::c_uint <= ch) as libc::c_int
    } else {
        xmlCharInRange(ch, &xmlIsBaseCharGroup)
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsBlank(mut ch: libc::c_uint) -> libc::c_int {
    return if ch < 0x100 as libc::c_int as libc::c_uint {
        (ch == 0x20 as libc::c_int as libc::c_uint
            || 0x9 as libc::c_int as libc::c_uint <= ch
                && ch <= 0xa as libc::c_int as libc::c_uint
            || ch == 0xd as libc::c_int as libc::c_uint) as libc::c_int
    } else {
        0 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsChar(mut ch: libc::c_uint) -> libc::c_int {
    return if ch < 0x100 as libc::c_int as libc::c_uint {
        (0x9 as libc::c_int as libc::c_uint <= ch
            && ch <= 0xa as libc::c_int as libc::c_uint
            || ch == 0xd as libc::c_int as libc::c_uint
            || 0x20 as libc::c_int as libc::c_uint <= ch) as libc::c_int
    } else {
        (0x100 as libc::c_int as libc::c_uint <= ch
            && ch <= 0xd7ff as libc::c_int as libc::c_uint
            || 0xe000 as libc::c_int as libc::c_uint <= ch
                && ch <= 0xfffd as libc::c_int as libc::c_uint
            || 0x10000 as libc::c_int as libc::c_uint <= ch
                && ch <= 0x10ffff as libc::c_int as libc::c_uint) as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsCombining(mut ch: libc::c_uint) -> libc::c_int {
    return if ch < 0x100 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        xmlCharInRange(ch, &xmlIsCombiningGroup)
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsDigit(mut ch: libc::c_uint) -> libc::c_int {
    return if ch < 0x100 as libc::c_int as libc::c_uint {
        (0x30 as libc::c_int as libc::c_uint <= ch
            && ch <= 0x39 as libc::c_int as libc::c_uint) as libc::c_int
    } else {
        xmlCharInRange(ch, &xmlIsDigitGroup)
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsExtender(mut ch: libc::c_uint) -> libc::c_int {
    return if ch < 0x100 as libc::c_int as libc::c_uint {
        (ch == 0xb7 as libc::c_int as libc::c_uint) as libc::c_int
    } else {
        xmlCharInRange(ch, &xmlIsExtenderGroup)
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsIdeographic(mut ch: libc::c_uint) -> libc::c_int {
    return if ch < 0x100 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        (0x4e00 as libc::c_int as libc::c_uint <= ch
            && ch <= 0x9fa5 as libc::c_int as libc::c_uint
            || ch == 0x3007 as libc::c_int as libc::c_uint
            || 0x3021 as libc::c_int as libc::c_uint <= ch
                && ch <= 0x3029 as libc::c_int as libc::c_uint) as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsPubidChar(mut ch: libc::c_uint) -> libc::c_int {
    return if ch < 0x100 as libc::c_int as libc::c_uint {
        xmlIsPubidChar_tab[ch as usize] as libc::c_int
    } else {
        0 as libc::c_int
    };
}
