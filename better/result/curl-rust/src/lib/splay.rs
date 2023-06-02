use :: libc;
pub type __time_t = i64;
pub type time_t = i64;
pub type curltime = crate::src::lib::http2::curltime;
pub type Curl_tree = crate::src::lib::http2::Curl_tree;
#[no_mangle]
pub extern "C" fn Curl_splay(
    mut i: crate::src::lib::http2::curltime,
    mut t: *mut crate::src::lib::http2::Curl_tree,
) -> *mut crate::src::lib::http2::Curl_tree {
    let mut N: crate::src::lib::http2::Curl_tree = Curl_tree {
        smaller: 0 as *mut Curl_tree,
        larger: 0 as *mut Curl_tree,
        samen: 0 as *mut Curl_tree,
        samep: 0 as *mut Curl_tree,
        key: curltime {
            tv_sec: 0,
            tv_usec: 0,
        },
        payload: 0 as *mut libc::c_void,
    };
    let mut l: *mut crate::src::lib::http2::Curl_tree = 0 as *mut Curl_tree;
    let mut r: *mut crate::src::lib::http2::Curl_tree = 0 as *mut Curl_tree;
    let mut y: *mut crate::src::lib::http2::Curl_tree = 0 as *mut Curl_tree;
    if t.is_null() {
        return t;
    }
    N.larger = 0 as *mut Curl_tree;
    N.smaller = N.larger;
    r = &mut N;
    l = r;
    loop {
        let mut comp: i64 = (if i.tv_sec < (unsafe { (*t).key.tv_sec }) {
            -(1 as i32)
        } else if i.tv_sec > (unsafe { (*t).key.tv_sec }) {
            1 as i32
        } else if i.tv_usec < (unsafe { (*t).key.tv_usec }) {
            -(1 as i32)
        } else if i.tv_usec > (unsafe { (*t).key.tv_usec }) {
            1 as i32
        } else {
            0 as i32
        }) as i64;
        if comp < 0 as i32 as i64 {
            if (unsafe { (*t).smaller }).is_null() {
                break;
            }
            if (if i.tv_sec < (unsafe { (*(*t).smaller).key.tv_sec }) {
                -(1 as i32)
            } else {
                if i.tv_sec > (unsafe { (*(*t).smaller).key.tv_sec }) {
                    1 as i32
                } else {
                    if i.tv_usec < (unsafe { (*(*t).smaller).key.tv_usec }) {
                        -(1 as i32)
                    } else {
                        if i.tv_usec > (unsafe { (*(*t).smaller).key.tv_usec }) {
                            1 as i32
                        } else {
                            0 as i32
                        }
                    }
                }
            }) < 0 as i32
            {
                y = unsafe { (*t).smaller };
                let mut fresh0 = unsafe { &mut ((*t).smaller) };
                *fresh0 = unsafe { (*y).larger };
                let mut fresh1 = unsafe { &mut ((*y).larger) };
                *fresh1 = t;
                t = y;
                if (unsafe { (*t).smaller }).is_null() {
                    break;
                }
            }
            let mut fresh2 = unsafe { &mut ((*r).smaller) };
            *fresh2 = t;
            r = t;
            t = unsafe { (*t).smaller };
        } else {
            if !(comp > 0 as i32 as i64) {
                break;
            }
            if (unsafe { (*t).larger }).is_null() {
                break;
            }
            if (if i.tv_sec < (unsafe { (*(*t).larger).key.tv_sec }) {
                -(1 as i32)
            } else {
                if i.tv_sec > (unsafe { (*(*t).larger).key.tv_sec }) {
                    1 as i32
                } else {
                    if i.tv_usec < (unsafe { (*(*t).larger).key.tv_usec }) {
                        -(1 as i32)
                    } else {
                        if i.tv_usec > (unsafe { (*(*t).larger).key.tv_usec }) {
                            1 as i32
                        } else {
                            0 as i32
                        }
                    }
                }
            }) > 0 as i32
            {
                y = unsafe { (*t).larger };
                let mut fresh3 = unsafe { &mut ((*t).larger) };
                *fresh3 = unsafe { (*y).smaller };
                let mut fresh4 = unsafe { &mut ((*y).smaller) };
                *fresh4 = t;
                t = y;
                if (unsafe { (*t).larger }).is_null() {
                    break;
                }
            }
            let mut fresh5 = unsafe { &mut ((*l).larger) };
            *fresh5 = t;
            l = t;
            t = unsafe { (*t).larger };
        }
    }
    let mut fresh6 = unsafe { &mut ((*l).larger) };
    *fresh6 = unsafe { (*t).smaller };
    let mut fresh7 = unsafe { &mut ((*r).smaller) };
    *fresh7 = unsafe { (*t).larger };
    let mut fresh8 = unsafe { &mut ((*t).smaller) };
    *fresh8 = N.larger;
    let mut fresh9 = unsafe { &mut ((*t).larger) };
    *fresh9 = N.smaller;
    return t;
}
#[no_mangle]
pub extern "C" fn Curl_splayinsert(
    mut i: crate::src::lib::http2::curltime,
    mut t: *mut crate::src::lib::http2::Curl_tree,
    mut node: *mut crate::src::lib::http2::Curl_tree,
) -> *mut crate::src::lib::http2::Curl_tree {
    static mut KEY_NOTUSED: crate::src::lib::http2::curltime = {
        let mut init = curltime {
            tv_sec: -(1 as i32) as time_t,
            tv_usec: -(1 as i32) as u32 as i32,
        };
        init
    };
    if node.is_null() {
        return t;
    }
    if !t.is_null() {
        t = Curl_splay(i, t);
        if (if i.tv_sec < (unsafe { (*t).key.tv_sec }) {
            -(1 as i32)
        } else {
            if i.tv_sec > (unsafe { (*t).key.tv_sec }) {
                1 as i32
            } else {
                if i.tv_usec < (unsafe { (*t).key.tv_usec }) {
                    -(1 as i32)
                } else {
                    if i.tv_usec > (unsafe { (*t).key.tv_usec }) {
                        1 as i32
                    } else {
                        0 as i32
                    }
                }
            }
        }) == 0 as i32
        {
            (unsafe { (*node).key = KEY_NOTUSED });
            let mut fresh10 = unsafe { &mut ((*node).samen) };
            *fresh10 = t;
            let mut fresh11 = unsafe { &mut ((*node).samep) };
            *fresh11 = unsafe { (*t).samep };
            let mut fresh12 = unsafe { &mut ((*(*t).samep).samen) };
            *fresh12 = node;
            let mut fresh13 = unsafe { &mut ((*t).samep) };
            *fresh13 = node;
            return t;
        }
    }
    if t.is_null() {
        let mut fresh14 = unsafe { &mut ((*node).larger) };
        *fresh14 = 0 as *mut Curl_tree;
        let mut fresh15 = unsafe { &mut ((*node).smaller) };
        *fresh15 = *fresh14;
    } else if (if i.tv_sec < (unsafe { (*t).key.tv_sec }) {
        -(1 as i32)
    } else {
        if i.tv_sec > (unsafe { (*t).key.tv_sec }) {
            1 as i32
        } else {
            if i.tv_usec < (unsafe { (*t).key.tv_usec }) {
                -(1 as i32)
            } else {
                if i.tv_usec > (unsafe { (*t).key.tv_usec }) {
                    1 as i32
                } else {
                    0 as i32
                }
            }
        }
    }) < 0 as i32
    {
        let mut fresh16 = unsafe { &mut ((*node).smaller) };
        *fresh16 = unsafe { (*t).smaller };
        let mut fresh17 = unsafe { &mut ((*node).larger) };
        *fresh17 = t;
        let mut fresh18 = unsafe { &mut ((*t).smaller) };
        *fresh18 = 0 as *mut Curl_tree;
    } else {
        let mut fresh19 = unsafe { &mut ((*node).larger) };
        *fresh19 = unsafe { (*t).larger };
        let mut fresh20 = unsafe { &mut ((*node).smaller) };
        *fresh20 = t;
        let mut fresh21 = unsafe { &mut ((*t).larger) };
        *fresh21 = 0 as *mut Curl_tree;
    }
    (unsafe { (*node).key = i });
    let mut fresh22 = unsafe { &mut ((*node).samen) };
    *fresh22 = node;
    let mut fresh23 = unsafe { &mut ((*node).samep) };
    *fresh23 = node;
    return node;
}
#[no_mangle]
pub extern "C" fn Curl_splaygetbest<'a1>(
    mut i: crate::src::lib::http2::curltime,
    mut t: *mut crate::src::lib::http2::Curl_tree,
    mut removed: Option<&'a1 mut *mut crate::src::lib::http2::Curl_tree>,
) -> *mut crate::src::lib::http2::Curl_tree {
    static mut tv_zero: crate::src::lib::http2::curltime = {
        let mut init = curltime {
            tv_sec: 0 as i32 as time_t,
            tv_usec: 0 as i32,
        };
        init
    };
    let mut x: *mut crate::src::lib::http2::Curl_tree = 0 as *mut Curl_tree;
    if t.is_null() {
        *(borrow_mut(&mut removed)).unwrap() = 0 as *mut Curl_tree;
        return 0 as *mut Curl_tree;
    }
    t = Curl_splay(unsafe { tv_zero }, t);
    if (if i.tv_sec < (unsafe { (*t).key.tv_sec }) {
        -(1 as i32)
    } else {
        if i.tv_sec > (unsafe { (*t).key.tv_sec }) {
            1 as i32
        } else {
            if i.tv_usec < (unsafe { (*t).key.tv_usec }) {
                -(1 as i32)
            } else {
                if i.tv_usec > (unsafe { (*t).key.tv_usec }) {
                    1 as i32
                } else {
                    0 as i32
                }
            }
        }
    }) < 0 as i32
    {
        *(borrow_mut(&mut removed)).unwrap() = 0 as *mut Curl_tree;
        return t;
    }
    x = unsafe { (*t).samen };
    if x != t {
        (unsafe { (*x).key = (*t).key });
        let mut fresh24 = unsafe { &mut ((*x).larger) };
        *fresh24 = unsafe { (*t).larger };
        let mut fresh25 = unsafe { &mut ((*x).smaller) };
        *fresh25 = unsafe { (*t).smaller };
        let mut fresh26 = unsafe { &mut ((*x).samep) };
        *fresh26 = unsafe { (*t).samep };
        let mut fresh27 = unsafe { &mut ((*(*t).samep).samen) };
        *fresh27 = x;
        *(borrow_mut(&mut removed)).unwrap() = t;
        return x;
    }
    x = unsafe { (*t).larger };
    *(borrow_mut(&mut removed)).unwrap() = t;
    return x;
}
#[no_mangle]
pub extern "C" fn Curl_splayremove<'a1>(
    mut t: *mut crate::src::lib::http2::Curl_tree,
    mut removenode: *mut crate::src::lib::http2::Curl_tree,
    mut newroot: Option<&'a1 mut *mut crate::src::lib::http2::Curl_tree>,
) -> i32 {
    static mut KEY_NOTUSED: crate::src::lib::http2::curltime = {
        let mut init = curltime {
            tv_sec: -(1 as i32) as time_t,
            tv_usec: -(1 as i32) as u32 as i32,
        };
        init
    };
    let mut x: *mut crate::src::lib::http2::Curl_tree = 0 as *mut Curl_tree;
    if t.is_null() || removenode.is_null() {
        return 1 as i32;
    }
    if (if (unsafe { KEY_NOTUSED.tv_sec }) < (unsafe { (*removenode).key.tv_sec }) {
        -(1 as i32)
    } else {
        if (unsafe { KEY_NOTUSED.tv_sec }) > (unsafe { (*removenode).key.tv_sec }) {
            1 as i32
        } else {
            if (unsafe { KEY_NOTUSED.tv_usec }) < (unsafe { (*removenode).key.tv_usec }) {
                -(1 as i32)
            } else {
                if (unsafe { KEY_NOTUSED.tv_usec }) > (unsafe { (*removenode).key.tv_usec }) {
                    1 as i32
                } else {
                    0 as i32
                }
            }
        }
    }) == 0 as i32
    {
        if (unsafe { (*removenode).samen }) == removenode {
            return 3 as i32;
        }
        let mut fresh28 = unsafe { &mut ((*(*removenode).samep).samen) };
        *fresh28 = unsafe { (*removenode).samen };
        let mut fresh29 = unsafe { &mut ((*(*removenode).samen).samep) };
        *fresh29 = unsafe { (*removenode).samep };
        let mut fresh30 = unsafe { &mut ((*removenode).samen) };
        *fresh30 = removenode;
        *(borrow_mut(&mut newroot)).unwrap() = t;
        return 0 as i32;
    }
    t = Curl_splay(unsafe { (*removenode).key }, t);
    if t != removenode {
        return 2 as i32;
    }
    x = unsafe { (*t).samen };
    if x != t {
        (unsafe { (*x).key = (*t).key });
        let mut fresh31 = unsafe { &mut ((*x).larger) };
        *fresh31 = unsafe { (*t).larger };
        let mut fresh32 = unsafe { &mut ((*x).smaller) };
        *fresh32 = unsafe { (*t).smaller };
        let mut fresh33 = unsafe { &mut ((*x).samep) };
        *fresh33 = unsafe { (*t).samep };
        let mut fresh34 = unsafe { &mut ((*(*t).samep).samen) };
        *fresh34 = x;
    } else if (unsafe { (*t).smaller }).is_null() {
        x = unsafe { (*t).larger };
    } else {
        x = Curl_splay(unsafe { (*removenode).key }, unsafe { (*t).smaller });
        let mut fresh35 = unsafe { &mut ((*x).larger) };
        *fresh35 = unsafe { (*t).larger };
    }
    *(borrow_mut(&mut newroot)).unwrap() = x;
    return 0 as i32;
}
use crate::laertes_rt::*;
