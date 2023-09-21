/// Fixtures and other constants
use crate::lazy_static::lazy_static;
use crate::{
    types::{Segment, Type},
    Name,
};
use std::collections::{HashMap, HashSet};
use DataFlowNode::*;

pub type FnName = String;

#[derive(Debug)]
pub enum DataFlowNode {
    /// Return value of an intrinsic function
    RetVal,
    /// Parameter of an intrinsic function
    Param(usize),
    /// Points-to set of another node
    PtsTo(Box<DataFlowNode>),
}

impl DataFlowNode {
    pub fn pts_to(pointer: DataFlowNode) -> DataFlowNode {
        PtsTo(Box::new(pointer))
    }
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
        "core::option::Option::unwrap",
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
    /// to emulate "volatile"
    pub static ref VOLATILE_FNS : HashSet<Name> = [
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
        "core::slice::<impl [T]>::as_ptr",
        "core::slice::<impl [T]>::as_ptr_range",
        "core::slice::<impl [T]>::as_mut_ptr",
        "core::slice::<impl [T]>::as_mut_ptr_range",
        "alloc::vec::Vec::as_ptr",
        "alloc::vec::Vec::as_mut_ptr",
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
        // The two arguments of offset_from should have the same type. Here, we
        // assume that the first parameter flows into the second one, so that we
        // handle the cases where it is owned (we cannot handle cases where both
        // need to be owned without reference counting, and our constraint
        // system cannot encode disjunctions (as they would prevent a minimum
        // solution while permitting minimal solutions to the constraint
        // system), otherwise we'd say param0 ⊆ param1 ∨ param1 ⊆ param0 to be
        // most flexible).
        ("core::ptr::mut_ptr::<impl *mut T>::offset_from", vec![(Param(0), Param(1)), (Param(1), Param(0))]),
        ("core::ptr::const_ptr::<impl *const T>::offset_from", vec![(Param(0), Param(1)), (Param(1), Param(0))]),
        ("core::ptr::mut_ptr::<impl *mut T>::add", vec![(Param(0), RetVal)]),
        ("core::ptr::mut_ptr::<impl *mut T>::sub", vec![(Param(0), RetVal)]),
        ("core::ptr::mut_ptr::<impl *mut T>::wrapping_add", vec![(Param(0), RetVal)]),
        ("core::ptr::mut_ptr::<impl *mut T>::wrapping_sub", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::align_offset", vec![]),
        ("core::ptr::const_ptr::<impl *const T>::offset", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::wrapping_offset", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::add", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::sub", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::wrapping_add", vec![(Param(0), RetVal)]),
        ("core::ptr::const_ptr::<impl *const T>::wrapping_sub", vec![(Param(0), RetVal)]),
        // null pointer creation and check
        ("core::ptr::mut_ptr::<impl *mut T>::is_null", vec![]),
        ("core::ptr::const_ptr::<impl *const T>::is_null", vec![]),
        ("core::ptr::mut_ptr::<impl *mut T>::null_mut", vec![]),
        ("core::ptr::const_ptr::<impl *const T>::null", vec![]),

        // Standard traits
        ("core::clone::Clone::clone", vec![(Param(0), RetVal)]),
        ("core::cmp::PartialEq::eq", vec![(Param(0), RetVal), (Param(1), RetVal)]),
        ("core::convert::AsMut::as_mut", vec![(Param(0), RetVal)]),
        ("core::convert::AsRef::as_ref", vec![(Param(0), RetVal)]),
        ("core::convert::Into::into", vec![(Param(0), RetVal)]),

        // Option
        ("core::option::Option::as_mut", vec![(Param(0), RetVal)]),
        ("core::option::Option::as_ref", vec![(Param(0), RetVal)]),
        ("core::option::Option::expect", vec![(Param(0), RetVal)]),
        ("core::option::Option::unwrap", vec![(Param(0), RetVal)]),
        ("core::option::Option::is_none", vec![]), // TODO: verify this
        ("core::option::Option::is_some", vec![]),
        ("core::option::Option::map", vec![(Param(0), Param(1)), (Param(1), RetVal)]),
        ("core::option::Option::map_or", vec![(Param(0), Param(2)), (Param(1), RetVal), (Param(2), RetVal)]),
        ("core::option::Option::unwrap", vec![(Param(0), RetVal)]),
        ("core::option::Option::Some", vec![(Param(0), RetVal)]),
        ("core::option::Option::None", vec![]),

        // RefCell
        ("core::cell::RefCell::borrow", vec![(Param(0), RetVal)]),
        ("core::cell::RefCell::borrow_mut", vec![(Param(0), RetVal)]),

        // Result
        ("core::result::Result::expect", vec![(Param(0), RetVal)]),
        ("core::result::Result::unwrap_or_else", vec![(Param(0), RetVal), (Param(0), Param(1)), (Param(1), RetVal)]),

        // Slice
        // slice->ptr conversion
        ("core::slice::<impl [T]>::as_mut_ptr", vec![(Param(0), RetVal)]),
        ("core::slice::<impl [T]>::as_mut_ptr_range", vec![(Param(0), RetVal)]),
        ("core::slice::<impl [T]>::as_ptr", vec![(Param(0), RetVal)]),
        ("core::slice::<impl [T]>::as_ptr_range", vec![(Param(0), RetVal)]),
        // slice len
        ("core::slice::<impl [T]>::len", vec![(Param(0), RetVal)]),

        // Vec
        // vec->ptr conversion
        ("alloc::vec::Vec::as_mut_ptr", vec![(Param(0), RetVal)]),
        ("alloc::vec::Vec::as_ptr", vec![(Param(0), RetVal)]),
        // vec len
        ("alloc::vec::Vec::len", vec![]),
        // vec push
        ("alloc::vec::Vec::push", vec![(Param(1), DataFlowNode::pts_to(Param(0)))]),
        // new vec
        ("alloc::vec::Vec::new", vec![]),

        // Box
        // new box
        ("alloc::boxed::Box::new", vec![]),

        // C strings
        ("std::ffi::c_str::CString::new", vec![]),
        ("std::ffi::c_str::CString::into_raw", vec![(Param(0), RetVal)]),

        // Iterators
        ("core::iter::traits::collect::IntoIterator::into_iter", vec![(Param(0), RetVal)]),
        ("core::iter::traits::Iterator::next", vec![(DataFlowNode::pts_to(Param(0)), RetVal)]),
        ("core::iter::traits::iterator::Iterator::next", vec![(DataFlowNode::pts_to(Param(0)), RetVal)]),
        ("core::convert::From::from", vec![(Param(0), RetVal)]),

        // Arithmetic
        ("core::num::<impl u8>::overflowing_mul", vec![]),
        ("core::num::<impl u8>::overflowing_add", vec![]),
        ("core::num::<impl u8>::overflowing_sub", vec![]),
        ("core::num::<impl u8>::overflowing_rem", vec![]),
        ("core::num::<impl u8>::overflowing_div", vec![]),
        ("core::num::<impl u16>::overflowing_mul", vec![]),
        ("core::num::<impl u16>::overflowing_add", vec![]),
        ("core::num::<impl u16>::overflowing_sub", vec![]),
        ("core::num::<impl u16>::overflowing_rem", vec![]),
        ("core::num::<impl u16>::overflowing_div", vec![]),
        ("core::num::<impl u32>::overflowing_mul", vec![]),
        ("core::num::<impl u32>::overflowing_add", vec![]),
        ("core::num::<impl u32>::overflowing_sub", vec![]),
        ("core::num::<impl u32>::overflowing_rem", vec![]),
        ("core::num::<impl u32>::overflowing_div", vec![]),
        ("core::num::<impl u64>::overflowing_mul", vec![]),
        ("core::num::<impl u64>::overflowing_add", vec![]),
        ("core::num::<impl u64>::overflowing_sub", vec![]),
        ("core::num::<impl u64>::overflowing_rem", vec![]),
        ("core::num::<impl u64>::overflowing_div", vec![]),
        ("core::num::<impl i8>::wrapping_mul", vec![]),
        ("core::num::<impl i8>::wrapping_add", vec![]),
        ("core::num::<impl i8>::wrapping_sub", vec![]),
        ("core::num::<impl i8>::wrapping_rem", vec![]),
        ("core::num::<impl i8>::wrapping_div", vec![]),
        ("core::num::<impl i16>::wrapping_mul", vec![]),
        ("core::num::<impl i16>::wrapping_add", vec![]),
        ("core::num::<impl i16>::wrapping_sub", vec![]),
        ("core::num::<impl i16>::wrapping_rem", vec![]),
        ("core::num::<impl i16>::wrapping_div", vec![]),
        ("core::num::<impl i32>::wrapping_mul", vec![]),
        ("core::num::<impl i32>::wrapping_add", vec![]),
        ("core::num::<impl i32>::wrapping_sub", vec![]),
        ("core::num::<impl i32>::wrapping_rem", vec![]),
        ("core::num::<impl i32>::wrapping_div", vec![]),
        ("core::num::<impl i64>::wrapping_mul", vec![]),
        ("core::num::<impl i64>::wrapping_add", vec![]),
        ("core::num::<impl i64>::wrapping_sub", vec![]),
        ("core::num::<impl i64>::wrapping_rem", vec![]),
        ("core::num::<impl i64>::wrapping_div", vec![]),
        ("core::num::<impl u8>::wrapping_mul", vec![]),
        ("core::num::<impl u8>::wrapping_add", vec![]),
        ("core::num::<impl u8>::wrapping_sub", vec![]),
        ("core::num::<impl u8>::wrapping_rem", vec![]),
        ("core::num::<impl u8>::wrapping_div", vec![]),
        ("core::num::<impl u16>::wrapping_mul", vec![]),
        ("core::num::<impl u16>::wrapping_add", vec![]),
        ("core::num::<impl u16>::wrapping_sub", vec![]),
        ("core::num::<impl u16>::wrapping_rem", vec![]),
        ("core::num::<impl u16>::wrapping_div", vec![]),
        ("core::num::<impl u32>::wrapping_mul", vec![]),
        ("core::num::<impl u32>::wrapping_add", vec![]),
        ("core::num::<impl u32>::wrapping_sub", vec![]),
        ("core::num::<impl u32>::wrapping_rem", vec![]),
        ("core::num::<impl u32>::wrapping_div", vec![]),
        ("core::num::<impl u32>::wrapping_neg", vec![]),
        ("core::num::<impl u64>::wrapping_mul", vec![]),
        ("core::num::<impl u64>::wrapping_add", vec![]),
        ("core::num::<impl u64>::wrapping_sub", vec![]),
        ("core::num::<impl u64>::wrapping_rem", vec![]),
        ("core::num::<impl u64>::wrapping_div", vec![]),
        ("core::num::<impl u64>::wrapping_neg", vec![]),
        ("core::num::<impl u64>::leading_zeros", vec![]),
        ("core::num::<impl u64>::trailing_zeros", vec![]),
        ("core::num::<impl i8>::wrapping_mul", vec![]),
        ("core::num::<impl i8>::wrapping_add", vec![]),
        ("core::num::<impl i8>::wrapping_sub", vec![]),
        ("core::num::<impl i8>::wrapping_rem", vec![]),
        ("core::num::<impl i8>::wrapping_div", vec![]),
        ("core::num::<impl i16>::wrapping_mul", vec![]),
        ("core::num::<impl i16>::wrapping_add", vec![]),
        ("core::num::<impl i16>::wrapping_sub", vec![]),
        ("core::num::<impl i16>::wrapping_rem", vec![]),
        ("core::num::<impl i16>::wrapping_div", vec![]),
        ("core::num::<impl i32>::wrapping_mul", vec![]),
        ("core::num::<impl i32>::wrapping_add", vec![]),
        ("core::num::<impl i32>::wrapping_sub", vec![]),
        ("core::num::<impl i32>::wrapping_rem", vec![]),
        ("core::num::<impl i32>::wrapping_div", vec![]),
        ("core::num::<impl i64>::wrapping_mul", vec![]),
        ("core::num::<impl i64>::wrapping_add", vec![]),
        ("core::num::<impl i64>::wrapping_sub", vec![]),
        ("core::num::<impl i64>::wrapping_rem", vec![]),
        ("core::num::<impl i64>::wrapping_div", vec![]),


        // Default trait
        ("core::default::Default::default", vec![]),

        // Memory ops
        ("core::mem::size_of", vec![]),

        // Ptr methods we support
        ("core::ptr::null", vec![]),
        ("core::ptr::null_mut", vec![]),

        // Transmute
        ("core::intrinsics::transmute", vec![(Param(0), RetVal)]),

        // Varargs
        ("core::ffi::VaListImpl::as_va_list", vec![(Param(0), RetVal)]),

        // Ranges
        ("core::ops::range::RangeInclusive::new", vec![]),
    ].into_iter().map(|(s, df)| (Name::from(s), df)).collect();

    pub static ref INJECTED_INTRINSICS: HashMap<Name, Vec<DataFlow>> = vec![
        ("__laertes_array::Get::get", vec![(DataFlowNode::pts_to(Param(0)), RetVal)]),
        ("__laertes_array::Get::get_add", vec![(DataFlowNode::pts_to(Param(0)), RetVal)]),
        ("__laertes_array::Get::get_sub", vec![(DataFlowNode::pts_to(Param(0)), RetVal)]),
        ("__laertes_array::Get::get_offset", vec![(DataFlowNode::pts_to(Param(0)), RetVal)]),
        ("__laertes_array::GetMut::get_mut", vec![(DataFlowNode::pts_to(Param(0)), RetVal)]),
        ("__laertes_array::GetMut::get_add_mut", vec![(DataFlowNode::pts_to(Param(0)), RetVal)]),
        ("__laertes_array::GetMut::get_sub_mut", vec![(DataFlowNode::pts_to(Param(0)), RetVal)]),
        ("__laertes_array::GetMut::get_offset_mut", vec![(DataFlowNode::pts_to(Param(0)), RetVal)]),
        ("__laertes_array::Slice::slice", vec![(Param(0), RetVal)]),
        ("__laertes_array::Slice::slice_add", vec![(Param(0), RetVal)]),
        ("__laertes_array::Slice::slice_sub", vec![(Param(0), RetVal)]),
        ("__laertes_array::Slice::slice_offset", vec![(Param(0), RetVal)]),
        ("__laertes_array::SliceMut::slice_mut", vec![(Param(0), RetVal)]),
        ("__laertes_array::SliceMut::slice_add_mut", vec![(Param(0), RetVal)]),
        ("__laertes_array::SliceMut::slice_sub_mut", vec![(Param(0), RetVal)]),
        ("__laertes_array::SliceMut::slice_offset_mut", vec![(Param(0), RetVal)]),
        ("__laertes_array::IntoSlice::into_slice", vec![(Param(0), RetVal)]),
        ("__laertes_array::SliceIndex::apply", vec![(Param(0), RetVal), (Param(1), RetVal)]),
        ("__laertes_array::CustomSlice::new", vec![(Param(0), RetVal)]),

        // malloc & free
        ("malloc", vec![]),
        ("free", vec![]),
    ].into_iter().map(|(s, df)| (Name::from(s), df)).collect();

/// Helper functions we generate
pub static ref LAERTES_HELPERS: [(&'static str, Vec<DataFlow>); 11] = [
    ("::borrow", vec![(Param(0), RetVal)]),
    ("::borrow_mut", vec![(Param(0), RetVal)]),
    ("::owned_as_ref", vec![(Param(0), RetVal)]),
    ("::owned_as_mut", vec![(Param(0), RetVal)]),
    ("::option_to_raw", vec![(Param(0), RetVal)]),
    ("::_ref_eq", vec![]),
    ("::_ref_ne", vec![]),
    ("::trans", vec![(Param(0), RetVal)]),
    ("::_as_mut_ptr", vec![]), //(Param(0), RetVal)]),
    ("::_as_ptr", vec![]), //(Param(0), RetVal)]),
    ("::_move_to_ptr", vec![]), //(Param(0), RetVal)]),
];

    pub static ref BOOL : Name = Name::from("bool");
    pub static ref CHAR : Name = Name::from("char");
    pub static ref STR : Name = Name::from("str");
    pub static ref C_VOID : Name = Name::from("core::ffi::c_void");
    pub static ref C_VOID_TYPE : Type = Type::Enum(Name::from("core::ffi::c_void"));
    pub static ref C_VOID_PATH : Vec<Segment> = vec!["core", "ffi", "c_void"].into_iter().map(|s| Segment::new(Name::from(s))).collect();
    pub static ref F128_TYPE : Type = Type::Unknown(vec!["f128", "f128"].into_iter().map(|s| Segment::new(Name::from(s))).collect());
    pub static ref KW_CRATE : Name = Name::from("crate");
    pub static ref TRANSMUTE_FN : Name = Name::from("core::intrinsics::transmute");

    /// Rewrites for some pointer methods that are straightforward
    pub static ref PTR_METHOD_REWRITES : HashMap<Name, String> = vec![
        ("core::ptr::mut_ptr::<impl *mut T>::is_null", "is_none"),
        ("core::ptr::const_ptr::<impl *const T>::is_null", "is_none"),
        ("core::ptr::mut_ptr::<impl *mut T>::null_mut", "None"),
        ("core::ptr::const_ptr::<impl *const T>::null", "None"),
    ].into_iter().map(|(k, v)| (Name::from(k), v.to_string())).collect();

    /// name for points-to constructor tag
    pub static ref REF : Name = Name::from("ref");

    /// name for function pointer tag, supporting up to 22 arguments
    pub static ref LAMBDA : Vec<Name> = (0..60).map(|i| Name::from(format!("λ{}", i))).collect();

    /// name for the function definition constructor to find function defintions
    /// in the program.
    pub static ref FNDEF : Name = Name::from("#fndef");

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
        "f32",
        "f64",
        "core::option::Option",
    ].into_iter().map(|s| s.split("::").map(Name::from).collect()).collect();

    /// Some known types with
    pub static ref CONST_DEFAULT_VALUE_EXPRS: HashMap<Vec<Name>, &'static str> = vec![
        ("std::os::raw::c_char", "0"),
        ("std::os::raw::c_schar", "0"),
        ("std::os::raw::c_uchar", "0"),
        ("std::os::raw::c_short", "0"),
        ("std::os::raw::c_ushort", "0"),
        ("std::os::raw::c_int", "0"),
        ("std::os::raw::c_uint", "0"),
        ("std::os::raw::c_long", "0"),
        ("std::os::raw::c_ulong", "0"),
        ("std::os::raw::c_longlong", "0"),
        ("std::os::raw::c_ulonglong", "0"),
        ("std::os::raw::c_float", "0.0"),
        ("std::os::raw::c_double", "0.0"),
        ("i8", "0"),
        ("u8", "0"),
        ("i16", "0"),
        ("u16", "0"),
        ("i32", "0"),
        ("u32", "0"),
        ("i64", "0"),
        ("u64", "0"),
        ("isize", "0"),
        ("usize", "0"),
        ("f32", "0.0"),
        ("f64", "0.0"),
        ("core::option::Option", "None"),
        ("f128_internal::f128_t::f128", "f128::f128::ZERO"),
        ("f128::f128", "f128::f128::ZERO"),
    ].into_iter().map(|(name, expr)| (name.split("::").map(Name::from).collect(), expr)).collect();

    /// Names of the primitive types that are kept as Unknown in syntactic translation
    pub static ref PRIMITIVE_TYPES: HashSet<Name> = vec![
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
        "f32",
        "f64",
        ].into_iter().map(Name::from).collect();

    /// Default value function for some types
    pub static ref DEFAULT_FN: HashMap<Vec<Name>, &'static str> = vec![
        ("core::ptr::mut_ptr", "core::ptr::null_mut"),
        ("core::ptr::const_ptr", "core::ptr::null"),
    ].into_iter().map(|(t, f)| (t.split("::").map(Name::from).collect(), f)).collect();

    /// C standard library types that we should not rewrite
    pub static ref LIBC_TYPES: HashSet<&'static str> = vec!["_RuneLocale", "_RuneCharClass", "_RuneRange", "_RuneEntry"].into_iter().collect();
}

/// Is this a special fn that is added by us or C2Rust before
/// create-initial-program
pub fn is_special_fn_in_benchmark(fn_name: &str) -> bool {
    fn_name.ends_with("::main")
        || fn_name.contains("bitfields::")
        || fn_name.ends_with("xmlschemastypes::get_bits")
        || fn_name.ends_with("xmlschemastypes::set_bits")
        || fn_name.contains("xmlschemastypes::_xmlSchemaValDate::")
        || fn_name.contains("xmlschemastypes::_xmlSchemaValDecimal::")
}

pub fn is_laertes_helper(fn_name: &str) -> bool {
    fn_name.contains("__laertes_array::")
        || fn_name.contains("laertes_rt::")
        || LAERTES_HELPERS
            .iter()
            .any(|(helper, _)| fn_name.ends_with(helper))
}
