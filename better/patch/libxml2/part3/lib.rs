#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![feature(asm)]
#![feature(c_variadic)]
#![feature(extern_types)]
#![feature(label_break_value)]
#![feature(register_tool)]
#![register_tool(c2rust)]
#![feature(rustc_private)]
#![feature(const_mut_refs)]
#![feature(const_fn_fn_ptr_basics)]
#[macro_use]
extern crate c2rust_bitfields;
extern crate c2rust_asm_casts;
extern crate libc;
pub mod src {
    // pub mod HTMLparser;
    // pub mod HTMLtree;
    // pub mod SAX;
    // pub mod SAX2;
    // pub mod buf;
    // pub mod c14n;
    // pub mod catalog;
    // pub mod chvalid;
    // pub mod debugXML;
    // pub mod dict;
    // pub mod encoding; 
    // pub mod entities;
    // pub mod error;
    // pub mod globals;
    // pub mod hash;
    // pub mod legacy;
    // pub mod list;
    // pub mod nanoftp;
    // pub mod nanohttp;
    // pub mod parser;
    // pub mod parserInternals;
    // pub mod pattern;
    // pub mod relaxng;
    // pub mod schematron; 
    // pub mod testdso;
    // pub mod threads;
    // pub mod tree;  
    // pub mod uri;
    // pub mod valid;
    // pub mod xinclude;  
    // pub mod xlink;
    // pub mod xmlIO;
    // pub mod xmlcatalog;
    // pub mod xmllint;
    // pub mod xmlmemory;
    // pub mod xmlmodule;
    // pub mod xmlreader;
    // pub mod xmlregexp;
    // pub mod xmlsave;
    // pub mod xmlstring;
    // pub mod xmlunicode;
    // pub mod xmlwriter;
    // pub mod xpointer; 
    // pub mod xzlib;
    // pub mod xmlschemas;
    // pub mod xmlschemastypes;
    pub mod xpath;
    pub mod python {
        pub mod libxml;
        pub mod libxml2_py;
        pub mod types;
    } // mod python
} // mod src
