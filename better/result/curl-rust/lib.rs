#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
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
extern crate libc;
pub mod src {
    pub mod lib {
        pub mod altsvc;
        pub mod amigaos;
        pub mod asyn_ares;
        pub mod asyn_thread;
        pub mod base64;
        pub mod bufref;
        pub mod c_hyper;
        pub mod conncache;
        pub mod connect;
        pub mod content_encoding;
        pub mod cookie;
        pub mod curl_addrinfo;
        pub mod curl_ctype;
        pub mod curl_des;
        pub mod curl_endian;
        pub mod curl_fnmatch;
        pub mod curl_get_line;
        pub mod curl_gethostname;
        pub mod curl_gssapi;
        pub mod curl_memrchr;
        pub mod curl_multibyte;
        pub mod curl_ntlm_core;
        pub mod curl_ntlm_wb;
        pub mod curl_path;
        pub mod curl_range;
        pub mod curl_rtmp;
        pub mod curl_sasl;
        pub mod curl_sspi;
        pub mod curl_threads;
        pub mod dict;
        pub mod doh;
        pub mod dotdot;
        pub mod dynbuf;
        pub mod easy;
        pub mod easygetopt;
        pub mod easyoptions;
        pub mod escape;
        pub mod file;
        pub mod fileinfo;
        pub mod formdata;
        pub mod ftp;
        pub mod ftplistparser;
        pub mod getenv;
        pub mod getinfo;
        pub mod gopher;
        pub mod hash;
        pub mod hmac;
        pub mod hostasyn;
        pub mod hostcheck;
        pub mod hostip;
        pub mod hostip4;
        pub mod hostip6;
        pub mod hostsyn;
        pub mod hsts;
        pub mod http;
        pub mod http2;
        pub mod http_aws_sigv4;
        pub mod http_chunks;
        pub mod http_digest;
        pub mod http_negotiate;
        pub mod http_ntlm;
        pub mod http_proxy;
        pub mod idn_win32;
        pub mod if2ip;
        pub mod imap;
        pub mod inet_ntop;
        pub mod inet_pton;
        pub mod krb5;
        pub mod ldap;
        pub mod llist;
        pub mod md4;
        pub mod md5;
        pub mod memdebug;
        pub mod mime;
        pub mod mprintf;
        pub mod mqtt;
        pub mod multi;
        pub mod netrc;
        pub mod non_ascii;
        pub mod nonblock;
        pub mod openldap;
        pub mod parsedate;
        pub mod pingpong;
        pub mod pop3;
        pub mod progress;
        pub mod psl;
        pub mod rand;
        pub mod rename;
        pub mod rtsp;
        pub mod select;
        pub mod sendf;
        pub mod setopt;
        pub mod sha256;
        pub mod share;
        pub mod slist;
        pub mod smb;
        pub mod smtp;
        pub mod socketpair;
        pub mod socks;
        pub mod socks_gssapi;
        pub mod socks_sspi;
        pub mod speedcheck;
        pub mod splay;
        pub mod strcase;
        pub mod strdup;
        pub mod strerror;
        pub mod strtok;
        pub mod strtoofft;
        pub mod system_win32;
        pub mod telnet;
        pub mod tftp;
        pub mod timeval;
        pub mod transfer;
        pub mod url;
        pub mod urlapi;
        pub mod vauth {
            pub mod cleartext;
            pub mod cram;
            pub mod digest;
            pub mod digest_sspi;
            pub mod gsasl;
            pub mod krb5_gssapi;
            pub mod krb5_sspi;
            pub mod ntlm;
            pub mod ntlm_sspi;
            pub mod oauth2;
            pub mod spnego_gssapi;
            pub mod spnego_sspi;
            pub mod vauth;
        }
         // mod vauth
        pub mod version;
        pub mod version_win32;
        pub mod vquic {
            pub mod ngtcp2;
            pub mod quiche;
            pub mod vquic;
        }
         // mod vquic
        pub mod vssh {
            pub mod libssh;
            pub mod libssh2;
            pub mod wolfssh;
        }
         // mod vssh
        pub mod vtls {
            pub mod bearssl;
            pub mod gskit;
            pub mod gtls;
            pub mod keylog;
            pub mod mbedtls;
            pub mod mbedtls_threadlock;
            pub mod mesalink;
            pub mod nss;
            pub mod openssl;
            pub mod rustls;
            pub mod schannel;
            pub mod schannel_verify;
            pub mod sectransp;
            pub mod vtls;
            pub mod wolfssl;
        }
         // mod vtls
        pub mod warnless;
        pub mod wildcard;
        pub mod x509asn1;
    }
     // mod lib
    pub mod src {
        pub mod slist_wc;
        pub mod tool_binmode;
        pub mod tool_bname;
        pub mod tool_cb_dbg;
        pub mod tool_cb_hdr;
        pub mod tool_cb_prg;
        pub mod tool_cb_rea;
        pub mod tool_cb_see;
        pub mod tool_cb_wrt;
        pub mod tool_cfgable;
        pub mod tool_convert;
        pub mod tool_dirhie;
        pub mod tool_doswin;
        pub mod tool_easysrc;
        pub mod tool_filetime;
        pub mod tool_formparse;
        pub mod tool_getparam;
        pub mod tool_getpass;
        pub mod tool_help;
        pub mod tool_helpers;
        pub mod tool_homedir;
        pub mod tool_hugehelp;
        pub mod tool_libinfo;
        pub mod tool_main;
        pub mod tool_msgs;
        pub mod tool_operate;
        pub mod tool_operhlp;
        pub mod tool_panykey;
        pub mod tool_paramhlp;
        pub mod tool_parsecfg;
        pub mod tool_progress;
        pub mod tool_setopt;
        pub mod tool_sleep;
        pub mod tool_strdup;
        pub mod tool_urlglob;
        pub mod tool_util;
        pub mod tool_vms;
        pub mod tool_writeout;
        pub mod tool_writeout_json;
        pub mod tool_xattr;
    }
     // mod src
}
 // This module is only injected into the rewritten programs, it is not used
                          // internally. So, disable unused function warnings.
#[allow(dead_code)]
pub(crate) mod __laertes_array {
    use std::{
        cell::{Ref, RefCell, RefMut},
        cmp::Ordering,
        convert::{TryFrom, TryInto},
        marker::PhantomData,
    };

    pub trait Get<'g, T: 'g> {
        fn get(&'g self, index: SliceIndex) -> T;

        fn get_add(&'g self, index: usize) -> T {
            self.get(SliceIndex::Add(index))
        }

        fn get_sub(&'g self, index: usize) -> T {
            self.get(SliceIndex::Sub(index))
        }

        fn get_offset(&'g self, index: isize) -> T {
            self.get(SliceIndex::Offset(index))
        }
    }

    pub trait GetMut<'g, T: 'g> {
        fn get_mut(&'g mut self, index: SliceIndex) -> T;

        fn get_add_mut(&'g mut self, index: usize) -> T {
            self.get_mut(SliceIndex::Add(index))
        }

        fn get_sub_mut(&'g mut self, index: usize) -> T {
            self.get_mut(SliceIndex::Sub(index))
        }

        fn get_offset_mut(&'g mut self, index: isize) -> T {
            self.get_mut(SliceIndex::Offset(index))
        }
    }

    pub trait IntoSlice<S>: Sized {
        fn into_slice(self, index: SliceIndex) -> S;

        fn into_slice_add(self, index: usize) -> S {
            self.into_slice(SliceIndex::Add(index))
        }

        fn into_slice_sub(self, index: usize) -> S {
            self.into_slice(SliceIndex::Sub(index))
        }

        fn into_slice_offset(self, index: isize) -> S {
            self.into_slice(SliceIndex::Offset(index))
        }
    }

    pub trait Slice<'s, S: 's> {
        fn slice(&'s self, index: SliceIndex) -> S;

        fn slice_add(&'s self, index: usize) -> S {
            self.slice(SliceIndex::Add(index))
        }

        fn slice_sub(&'s self, index: usize) -> S {
            self.slice(SliceIndex::Sub(index))
        }

        fn slice_offset(&'s self, index: isize) -> S {
            self.slice(SliceIndex::Offset(index))
        }
    }

    pub trait SliceMut<'s, S: 's> {
        fn slice_mut(&'s mut self, index: SliceIndex) -> S;

        fn slice_add_mut(&'s mut self, index: usize) -> S {
            self.slice_mut(SliceIndex::Add(index))
        }

        fn slice_sub_mut(&'s mut self, index: usize) -> S {
            self.slice_mut(SliceIndex::Sub(index))
        }

        fn slice_offset_mut(&'s mut self, index: isize) -> S {
            self.slice_mut(SliceIndex::Offset(index))
        }
    }

    #[derive(Clone, Copy)]
    pub enum SliceIndex {
        Add(usize),
        Sub(usize),
        Offset(isize),
    }

    impl SliceIndex {
        fn apply(self, offset: usize) -> usize {
            match self {
                SliceIndex::Add(i) => offset.checked_add(i),
                SliceIndex::Sub(i) => offset.checked_sub(i),
                SliceIndex::Offset(i) => {
                    if i < 0 {
                        offset.checked_sub(i.wrapping_abs() as usize)
                    } else {
                        offset.checked_add(i as usize)
                    }
                }
            }
            .unwrap()
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct CustomSlice<'a, T: 'a, S: 'a> {
        offset: usize,
        slice: S,
        m: PhantomData<&'a T>,
    }

    impl<'a, T: 'a, S: 'a> CustomSlice<'a, T, S> {
        pub const fn new(slice: S) -> CustomSlice<'a, T, S> {
            CustomSlice {
                offset: 0,
                slice,
                m: PhantomData,
            }
        }
    }

    impl<'a, T: 'a> CustomSlice<'a, T, Box<[T]>> {
        pub fn boxed_from_vec(vec: Vec<T>) -> CustomSlice<'a, T, Box<[T]>> {
            CustomSlice {
                offset: 0,
                slice: vec.into_boxed_slice(),
                m: PhantomData::default(),
            }
        }
    }

    impl<'a, T: 'a, S: TryFrom<Vec<RefCell<T>>> + 'a> CustomSlice<'a, T, S> {
        pub fn from_vec(vec: Vec<T>) -> CustomSlice<'a, T, S> {
            CustomSlice::new(
                vec.into_iter()
                    .map(|v| RefCell::new(v))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap_or_else(|_| panic!("couldn't construct backing slice")),
            )
        }
    }

    impl<'a, T, S> IntoSlice<CustomSlice<'a, T, S>> for CustomSlice<'a, T, S> {
        fn into_slice(self, index: SliceIndex) -> CustomSlice<'a, T, S> {
            let CustomSlice { offset, slice, m } = self;

            CustomSlice {
                offset: index.apply(offset),
                slice,
                m,
            }
        }
    }

    impl<'a, 's, T, S: AsRef<[T]> + 's> Slice<'s, CustomSlice<'s, T, &'s [T]>>
        for CustomSlice<'a, T, S>
    {
        fn slice(&'s self, index: SliceIndex) -> CustomSlice<'s, T, &'s [T]> {
            let CustomSlice {
                offset,
                ref slice,
                m,
            } = *self;

            CustomSlice {
                offset: index.apply(offset),
                slice: slice.as_ref(),
                m,
            }
        }
    }

    impl<'a, 's, T, S: AsRef<[RefCell<T>]> + 's> Slice<'s, CustomSlice<'s, T, &'s [RefCell<T>]>>
        for CustomSlice<'a, T, S>
    {
        fn slice(&'s self, index: SliceIndex) -> CustomSlice<'s, T, &'s [RefCell<T>]> {
            let CustomSlice {
                offset,
                ref slice,
                m,
            } = *self;

            CustomSlice {
                offset: index.apply(offset),
                slice: slice.as_ref(),
                m,
            }
        }
    }

    impl<'a, 's, T, S: AsMut<[T]> + 's> SliceMut<'s, CustomSlice<'s, T, &'s mut [T]>>
        for CustomSlice<'a, T, S>
    {
        fn slice_mut(&'s mut self, index: SliceIndex) -> CustomSlice<'s, T, &'s mut [T]> {
            let CustomSlice {
                offset,
                ref mut slice,
                m,
            } = *self;

            CustomSlice {
                offset: index.apply(offset),
                slice: slice.as_mut(),
                m,
            }
        }
    }

    impl<'a, 'g, T, S: AsRef<[T]> + 'g> Get<'g, &'g T> for CustomSlice<'a, T, S> {
        fn get(&'g self, index: SliceIndex) -> &'g T {
            &self.slice.as_ref()[index.apply(self.offset)]
        }
    }

    impl<'a, 'g, T, S: AsMut<[T]> + 'g> GetMut<'g, &'g mut T> for CustomSlice<'a, T, S> {
        fn get_mut(&'g mut self, index: SliceIndex) -> &'g mut T {
            &mut self.slice.as_mut()[index.apply(self.offset)]
        }
    }

    impl<'a, 'g, T, S: AsRef<[RefCell<T>]> + 'g> Get<'g, Ref<'g, T>> for CustomSlice<'a, T, S> {
        fn get(&'g self, index: SliceIndex) -> Ref<'g, T> {
            self.slice.as_ref()[index.apply(self.offset)].borrow()
        }
    }

    impl<'a, 'g, T, S: AsRef<[RefCell<T>]> + 'g> Get<'g, RefMut<'g, T>> for CustomSlice<'a, T, S> {
        fn get(&'g self, index: SliceIndex) -> RefMut<'g, T> {
            self.slice.as_ref()[index.apply(self.offset)].borrow_mut()
        }
    }

    pub trait GetPtr<T: ?Sized> {
        fn get_ptr(&self) -> *const ();
    }

    impl<T: ?Sized> GetPtr<T> for &T {
        fn get_ptr(&self) -> *const () {
            *self as *const T as *const ()
        }
    }

    impl<T: ?Sized> GetPtr<T> for &mut T {
        fn get_ptr(&self) -> *const () {
            *self as *const T as *const ()
        }
    }

    impl<T> GetPtr<T> for &[T] {
        fn get_ptr(&self) -> *const () {
            self.as_ptr() as *const ()
        }
    }

    impl<T> GetPtr<T> for &mut [T] {
        fn get_ptr(&self) -> *const () {
            self.as_ptr() as *const ()
        }
    }

    impl<T> GetPtr<T> for Box<[T]> {
        fn get_ptr(&self) -> *const () {
            (*self).as_ptr() as *const ()
        }
    }

    impl<T: ?Sized> GetPtr<T> for Box<T> {
        fn get_ptr(&self) -> *const () {
            self.as_ref() as *const T as *const ()
        }
    }

    pub fn offset_from<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> isize {
        if l.is_none() && r.is_none() {
            return 0; // case for NULL - NULL
        }

        l.as_ref()
            .and_then(|l| {
                r.as_ref().map(|r| {
                    if l.slice.get_ptr() == r.slice.get_ptr() {
                        l.offset as isize - r.offset as isize
                    } else {
                        panic!("trying to compute offsets from two unrelated slices");
                    }
                })
            })
            .expect("tried to compare non-null and null pointers")
    }

    pub fn partial_cmp<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> Option<Ordering> {
        l.as_ref().and_then(|l| {
            r.as_ref().and_then(|r| {
                if l.slice.get_ptr() == r.slice.get_ptr() {
                    Some(l.offset.cmp(&r.offset))
                } else {
                    None
                }
            })
        })
    }

    pub fn partial_lt<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> Option<bool> {
        partial_cmp(l, r).map(|c| c == Ordering::Less)
    }
    pub fn partial_gt<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> Option<bool> {
        partial_cmp(l, r).map(|c| c == Ordering::Greater)
    }
    pub fn partial_le<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> Option<bool> {
        partial_cmp(l, r).map(|c| c != Ordering::Greater)
    }
    pub fn partial_ge<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> Option<bool> {
        partial_cmp(l, r).map(|c| c != Ordering::Less)
    }

    pub fn compare_eq<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> bool {
        partial_cmp(l, r).map_or(false, |c| c == Ordering::Equal)
    }
    pub fn compare_ne<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> bool {
        !compare_eq(l, r)
    }

    pub fn compare_lt<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> bool {
        partial_lt(l, r).unwrap()
    }
    pub fn compare_gt<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> bool {
        partial_gt(l, r).unwrap()
    }
    pub fn compare_le<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> bool {
        partial_le(l, r).unwrap()
    }
    pub fn compare_ge<'a, T, L: GetPtr<T>, R: GetPtr<T>>(
        l: &Option<CustomSlice<'a, T, L>>,
        r: &Option<CustomSlice<'a, T, R>>,
    ) -> bool {
        partial_ge(l, r).unwrap()
    }

    pub fn borrow<'a, 'b: 'a, S: Slice<'a, T>, T: 'a>(s: &'b Option<S>) -> Option<T> {
        s.as_ref().map(|s| s.slice_add(0))
    }
    pub fn borrow_mut<'a, 'b: 'a, S: SliceMut<'a, T>, T: 'a>(s: &'b mut Option<S>) -> Option<T> {
        s.as_mut().map(|s| s.slice_add_mut(0))
    }
}

#[allow(dead_code)]
pub(crate) mod laertes_rt {
    use super::__laertes_array::GetPtr;

    pub trait Borrow<'b, T: ?Sized> {
        fn borrow<'a>(&'a self) -> Option<&'a T>
        where
            'b: 'a;
    }

    pub trait BorrowMut<'b, T: ?Sized> {
        fn borrow_mut<'a>(&'a mut self) -> Option<&'a mut T>
        where
            'b: 'a;
    }

    impl<'b, T: ?Sized> Borrow<'b, T> for Option<&'b mut T> {
        fn borrow<'a>(&'a self) -> Option<&'a T>
        where
            'b: 'a,
        {
            self.as_ref().map(|x| &**x)
        }
    }

    impl<'b, T: ?Sized> BorrowMut<'b, T> for Option<&'b mut T> {
        fn borrow_mut<'a>(&'a mut self) -> Option<&'a mut T>
        where
            'b: 'a,
        {
            self.as_mut().map(|x| &mut **x)
        }
    }

    impl<'b, T: ?Sized> Borrow<'b, T> for Option<Box<T>> {
        fn borrow<'a>(&'a self) -> Option<&'a T>
        where
            'b: 'a,
        {
            self.as_ref().map(|x| x.as_ref())
        }
    }

    impl<'b, T: ?Sized> BorrowMut<'b, T> for Option<Box<T>> {
        fn borrow_mut<'a>(&'a mut self) -> Option<&'a mut T>
        where
            'b: 'a,
        {
            self.as_mut().map(|x| x.as_mut())
        }
    }

    pub fn borrow<'a, 'b: 'a, T: ?Sized, P: Borrow<'b, T>>(p: &'a P) -> Option<&'a T> {
        Borrow::borrow(p)
    }

    pub fn borrow_mut<'a, 'b: 'a, T: ?Sized, P: BorrowMut<'b, T>>(
        p: &'a mut P,
    ) -> Option<&'a mut T> {
        BorrowMut::borrow_mut(p)
    }

    pub fn owned_as_ref<'a, T>(p: &'a Option<Box<T>>) -> Option<&'a T> {
        p.as_ref().map(|x| x.as_ref())
    }

    pub fn owned_as_mut<'a, T>(p: &'a mut Option<Box<T>>) -> Option<&'a mut T> {
        p.as_mut().map(|x| x.as_mut())
    }

    pub fn option_to_raw<T: ?Sized, P: GetPtr<T>>(p: &Option<P>) -> *const () {
        p.as_ref()
            .map_or(core::ptr::null(), |p| p.get_ptr() as *const ())
    }

    pub fn _ref_eq<T: ?Sized, L: GetPtr<T>, R: GetPtr<T>>(p: Option<L>, q: Option<R>) -> bool {
        option_to_raw(&p) == option_to_raw(&q)
    }

    pub fn _ref_ne<T: ?Sized, L: GetPtr<T>, R: GetPtr<T>>(p: Option<L>, q: Option<R>) -> bool {
        option_to_raw(&p) != option_to_raw(&q)
    }

    // functions to convert references to raw pointers
    pub fn _as_ptr<T, P: GetPtr<T>>(r: &Option<P>) -> *const T {
        option_to_raw(r) as *const T
    }

    pub fn _as_mut_ptr<T, P: GetPtr<T>>(r: &mut Option<P>) -> *mut T {
        option_to_raw(r) as *const T as *mut T
    }

    pub fn _move_to_ptr<T>(b: Option<Box<T>>) -> *mut T {
        b.map_or(core::ptr::null_mut(), Box::into_raw)
    }

    pub fn trans<'a, 'b, T: 'a, U: 'b>(_: T) -> U
    where
        'a: 'b,
    {
        loop {}
    }
}

 // mod src
