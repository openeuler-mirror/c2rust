/// Fixtures and other constants
use crate::lazy_static::lazy_static;
use crate::{types::Segment, Name};
use std::collections::{HashMap, HashSet};
use DataFlowNode::*;

pub type FnName = String;

pub enum DataFlowNode {
    RetVal,
    Param(usize),
}

pub type DataFlow = (DataFlowNode, DataFlowNode);

lazy_static! {
    pub static ref C_FNS_WE_HANDLE : HashSet<String> = [
    "malloc",
    "calloc",
    "free",
    ].iter().map(|s| s.to_string()).collect();
    pub static ref RUST_FNS_WE_HANDLE : HashSet<String> = [
        "core::intrinsics::transmute",
        // The part below is safe function calls to the Rust standard
        // library. A better option would be to check safety by
        // resolving the function definitions when building the call
        // graph.
        "core::mem::size_of",
        "core::option::Option::is_none",
        "core::option::Option::is_some",
        "core::option::Option::expect",
        "core::option::Option::Some",
        "core::num::<impl u64>::wrapping_div",
        "core::num::<impl u64>::wrapping_div",
        "core::ptr::mut_ptr::<impl *mut T>::is_null",
        "core::ptr::const_ptr::<impl *const T>::is_null",
        "core::num::<impl u64>::wrapping_add",
        "core::num::<impl u64>::wrapping_sub",
        "core::slice::<impl [T]>::as_ptr",
    ].iter().map(|s| s.to_string()).collect();

    /// Methods on pointer types that dereference the pointer
    pub static ref DEREF_METHODS : HashSet<Name> = [
        "core::ptr::mut_ptr::<impl *mut T>::as_mut",
        "core::ptr::mut_ptr::<impl *mut T>::as_ref",
        "core::ptr::mut_ptr::<impl *mut T>::read",
        "core::ptr::mut_ptr::<impl *mut T>::read_volatile",
        "core::ptr::mut_ptr::<impl *mut T>::read_unaligned",
        "core::ptr::mut_ptr::<impl *mut T>::copy_to",
        "core::ptr::mut_ptr::<impl *mut T>::copy_to_nonoverlapping",
        "core::ptr::const_ptr::<impl *const T>::as_ref",
        "core::ptr::const_ptr::<impl *const T>::read",
        "core::ptr::const_ptr::<impl *const T>::read_volatile",
        "core::ptr::const_ptr::<impl *const T>::read_unaligned",
        "core::ptr::const_ptr::<impl *const T>::copy_to",
        "core::ptr::const_ptr::<impl *const T>::copy_to_nonoverlapping",
    ].iter().map(|s| Name::from(*s)).collect();

    /// Standard library functions that require a raw pointer argument
    pub static ref FNS_REQUIRING_RAW_PTR : HashSet<Name> = [
        "core::ptr::write_volatile",
    ].iter().map(|s| Name::from(*s)).collect();

    /// Pointer arithmetic methods with data flow edges that we care about
    pub static ref PTR_ARITH_METHODS : HashSet<Name> = [
        "core::ptr::mut_ptr::<impl *mut T>::align_offset",
        "core::ptr::mut_ptr::<impl *mut T>::offset",
        "core::ptr::mut_ptr::<impl *mut T>::wrapping_offset",
        "core::ptr::mut_ptr::<impl *mut T>::offset_from",
        "core::ptr::mut_ptr::<impl *mut T>::add",
        "core::ptr::mut_ptr::<impl *mut T>::sub",
        "core::ptr::mut_ptr::<impl *mut T>::wrapping_add",
        "core::ptr::mut_ptr::<impl *mut T>::wrapping_sub",
        "core::ptr::const_ptr::<impl *const T>::align_offset",
        "core::ptr::const_ptr::<impl *const T>::offset",
        "core::ptr::const_ptr::<impl *const T>::wrapping_offset",
        "core::ptr::const_ptr::<impl *const T>::offset_from",
        "core::ptr::const_ptr::<impl *const T>::add",
        "core::ptr::const_ptr::<impl *const T>::sub",
        "core::ptr::const_ptr::<impl *const T>::wrapping_add",
        "core::ptr::const_ptr::<impl *const T>::wrapping_sub",
    ].iter().map(|s| Name::from(*s)).collect();

    /// Compiler intrinsics, or otherwise specially treated functions
    /// with specified data flow edges that we care about. This
    /// information is used for inlining these functions inside the
    /// the taint analysis.
    pub static ref COMPILER_INTRINSICS: HashMap<Name, Vec<DataFlow>> = vec![
        // Pointer dereference and copy methods
        ("core::ptr::mut_ptr::<impl *mut T>::as_mut", vec![(Param(0), RetVal)]),
        ("core::ptr::mut_ptr::<impl *mut T>::as_ref", vec![(Param(0), RetVal)]),
        ("core::ptr::mut_ptr::<impl *mut T>::copy_to", vec![(Param(0), Param(1))]),
        ("core::ptr::mut_ptr::<impl *mut T>::copy_to_nonoverlapping", vec![(Param(0), Param(1))]),
        ("core::ptr::const_ptr::<impl *const T>::as_ref", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::copy_to", vec![(Param(0), Param(1))]),
        ("core::ptr::const_ptr::<impl *const T>::copy_to_nonoverlapping", vec![(Param(0), Param(1))]),
        // dereference methods with no data flow
        ("core::ptr::mut_ptr::<impl *mut T>::read", vec![]),
        ("core::ptr::mut_ptr::<impl *mut T>::read_volatile", vec![]),
        ("core::ptr::mut_ptr::<impl *mut T>::read_unaligned", vec![]),
        ("core::ptr::const_ptr::<impl *const T>::read", vec![]),
        ("core::ptr::const_ptr::<impl *const T>::read_volatile", vec![]),
        ("core::ptr::const_ptr::<impl *const T>::read_unaligned", vec![]),
        // Pointer arithmetic methods
        ("core::ptr::mut_ptr::<impl *mut T>::align_offset", vec![]),
        ("core::ptr::mut_ptr::<impl *mut T>::offset", vec![(Param(0), RetVal)]),
        ("core::ptr::mut_ptr::<impl *mut T>::wrapping_offset", vec![(Param(0), RetVal)]),
        ("core::ptr::mut_ptr::<impl *mut T>::offset_from", vec![]),
        ("core::ptr::mut_ptr::<impl *mut T>::add", vec![(Param(0), RetVal)]),
        ("core::ptr::mut_ptr::<impl *mut T>::sub", vec![(Param(0), RetVal)]),
        ("core::ptr::mut_ptr::<impl *mut T>::wrapping_add", vec![(Param(0), RetVal)]),
        ("core::ptr::mut_ptr::<impl *mut T>::wrapping_sub", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::align_offset", vec![]),
        ("core::ptr::const_ptr::<impl *const T>::offset", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::wrapping_offset", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::offset_from", vec![]),
        ("core::ptr::const_ptr::<impl *const T>::add", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::sub", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::wrapping_add", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::wrapping_sub", vec![(Param(0), RetVal)]),
        // null pointer creation and check
        ("core::ptr::mut_ptr::<impl *mut T>::is_null", vec![]),
        ("core::ptr::const_ptr::<impl *const T>::is_null", vec![]),
        ("core::ptr::mut_ptr::<impl *mut T>::null_mut", vec![]),
        ("core::ptr::const_ptr::<impl *const T>::null", vec![]),
        // malloc & free
        ("malloc", vec![]),
        ("free", vec![]),
    ].into_iter().map(|(s, df)| (Name::from(s), df)).collect();

    pub static ref BOOL : Name = Name::from("bool");
    pub static ref CHAR : Name = Name::from("char");
    pub static ref STR : Name = Name::from("str");
    pub static ref C_VOID : Name = Name::from("core::ffi::c_void");
    pub static ref C_VOID_PATH : Vec<Segment> = vec!["core", "ffi", "c_void"].into_iter().map(|s| Segment::new(Name::from(s))).collect();
    pub static ref KW_CRATE : Name = Name::from("crate");
    pub static ref TRANSMUTE_FN : Name = Name::from("core::intrinsics::transmute");

    /// Rewrites for some pointer methods that are straightforward
    pub static ref PTR_METHOD_REWRITES : HashMap<Name, String> = vec![
        ("core::ptr::mut_ptr::<impl *mut T>::is_null", "is_none"),
        ("core::ptr::const_ptr::<impl *const T>::is_null", "is_none"),
        ("core::ptr::mut_ptr::<impl *mut T>::null_mut", "None"),
        ("core::ptr::const_ptr::<impl *const T>::null", "None"),
    ].into_iter().map(|(k, v)| (Name::from(k), v.to_string())).collect();

    // name for points-to constructor tag
    pub static ref REF : Name = Name::from("ref");


    /// Types from the compiler that implement `Default` trait
    pub static ref IMPLEMENTS_DEFAULT: HashSet<Vec<Name>> = vec![
        "std::os::raw::c_char",
        "std::os::raw::c_schar",
        "std::os::raw::c_uchar",
        "std::os::raw::c_short",
        "std::os::raw::c_ushort",
        "std::os::raw::c_int",
        "std::os::raw::c_uint",
        "std::os::raw::c_long",
        "std::os::raw::c_ulong",
        "std::os::raw::c_longlong",
        "std::os::raw::c_ulonglong",
        "std::os::raw::c_float",
        "std::os::raw::c_double",
        "i8",
        "u8",
        "i16",
        "u16",
        "i32",
        "u32",
        "i64",
        "u64",
        "isize",
        "usize",
        "core::option::Option",
    ].into_iter().map(|s| s.split("::").map(Name::from).collect()).collect();

    /// Default value function for some types
    pub static ref DEFAULT_FN: HashMap<Vec<Name>, &'static str> = vec![
        ("core::ptr::mut_ptr", "core::ptr::null_mut"),
        ("core::ptr::const_ptr", "core::ptr::null"),
    ].into_iter().map(|(t, f)| (t.split("::").map(Name::from).collect(), f)).collect();

    /// C standard library types that we should not rewrite
    pub static ref LIBC_TYPES: HashSet<&'static str> = vec!["_RuneLocale", "_RuneCharClass", "_RuneRange", "_RuneEntry"].into_iter().collect();
}
