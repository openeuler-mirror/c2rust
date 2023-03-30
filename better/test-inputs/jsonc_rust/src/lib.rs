#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![feature(c_variadic)]
#![feature(core_intrinsics)]
#![feature(extern_types)]
#![feature(label_break_value)]
#![feature(register_tool)]
#![feature(thread_local)]
#![register_tool(c2rust)]
#![feature(rustc_private)]

extern crate libc;

pub mod apps {
pub mod json_parse;
} // mod apps
pub mod arraylist;
pub mod debug;
pub mod json_c_version;
pub mod json_object;
pub mod json_object_iterator;
pub mod json_pointer;
pub mod json_tokener;
pub mod json_util;
pub mod json_visit;
pub mod linkhash;
pub mod printbuf;
pub mod random_seed;
pub mod strerror_override;
pub mod tests {
pub mod parse_flags;
pub mod test1;
pub mod test2;
pub mod test4;
pub mod testReplaceExisting;
pub mod test_cast;
pub mod test_charcase;
pub mod test_compare;
pub mod test_deep_copy;
pub mod test_double_serializer;
pub mod test_float;
pub mod test_int_add;
pub mod test_int_get;
pub mod test_json_pointer;
pub mod test_locale;
pub mod test_null;
pub mod test_object_iterator;
pub mod test_parse;
pub mod test_parse_int64;
pub mod test_printbuf;
pub mod test_set_serializer;
pub mod test_set_value;
pub mod test_strerror;
pub mod test_util_file;
pub mod test_visit;
} // mod tests
