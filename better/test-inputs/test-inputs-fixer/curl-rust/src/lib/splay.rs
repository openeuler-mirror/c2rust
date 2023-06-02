use :: libc;
pub type __time_t = i64;
pub type time_t = __time_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curltime {
    pub tv_sec: time_t,
    pub tv_usec: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_tree {
    pub smaller: *mut Curl_tree,
    pub larger: *mut Curl_tree,
    pub samen: *mut Curl_tree,
    pub samep: *mut Curl_tree,
    pub key: curltime,
    pub payload: *mut libc::c_void,
}
#[no_mangle]
pub extern "C" fn Curl_splay(mut i: curltime, mut t: *mut Curl_tree) -> *mut Curl_tree {
    let mut N: Curl_tree = Curl_tree {
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
    let mut l: *mut Curl_tree = 0 as *mut Curl_tree;
    let mut r: *mut Curl_tree = 0 as *mut Curl_tree;
    let mut y: *mut Curl_tree = 0 as *mut Curl_tree;
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
                let fresh0 = unsafe { &mut ((*t).smaller) };
                *fresh0 = unsafe { (*y).larger };
                let fresh1 = unsafe { &mut ((*y).larger) };
                *fresh1 = t;
                t = y;
                if (unsafe { (*t).smaller }).is_null() {
                    break;
                }
            }
            let fresh2 = unsafe { &mut ((*r).smaller) };
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
                let fresh3 = unsafe { &mut ((*t).larger) };
                *fresh3 = unsafe { (*y).smaller };
                let fresh4 = unsafe { &mut ((*y).smaller) };
                *fresh4 = t;
                t = y;
                if (unsafe { (*t).larger }).is_null() {
                    break;
                }
            }
            let fresh5 = unsafe { &mut ((*l).larger) };
            *fresh5 = t;
            l = t;
            t = unsafe { (*t).larger };
        }
    }
    let fresh6 = unsafe { &mut ((*l).larger) };
    *fresh6 = unsafe { (*t).smaller };
    let fresh7 = unsafe { &mut ((*r).smaller) };
    *fresh7 = unsafe { (*t).larger };
    let fresh8 = unsafe { &mut ((*t).smaller) };
    *fresh8 = N.larger;
    let fresh9 = unsafe { &mut ((*t).larger) };
    *fresh9 = N.smaller;
    return t;
}
#[no_mangle]
pub extern "C" fn Curl_splayinsert(
    mut i: curltime,
    mut t: *mut Curl_tree,
    mut node: *mut Curl_tree,
) -> *mut Curl_tree {
    static mut KEY_NOTUSED: curltime = {
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
            let fresh10 = unsafe { &mut ((*node).samen) };
            *fresh10 = t;
            let fresh11 = unsafe { &mut ((*node).samep) };
            *fresh11 = unsafe { (*t).samep };
            let fresh12 = unsafe { &mut ((*(*t).samep).samen) };
            *fresh12 = node;
            let fresh13 = unsafe { &mut ((*t).samep) };
            *fresh13 = node;
            return t;
        }
    }
    if t.is_null() {
        let fresh14 = unsafe { &mut ((*node).larger) };
        *fresh14 = 0 as *mut Curl_tree;
        let fresh15 = unsafe { &mut ((*node).smaller) };
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
        let fresh16 = unsafe { &mut ((*node).smaller) };
        *fresh16 = unsafe { (*t).smaller };
        let fresh17 = unsafe { &mut ((*node).larger) };
        *fresh17 = t;
        let fresh18 = unsafe { &mut ((*t).smaller) };
        *fresh18 = 0 as *mut Curl_tree;
    } else {
        let fresh19 = unsafe { &mut ((*node).larger) };
        *fresh19 = unsafe { (*t).larger };
        let fresh20 = unsafe { &mut ((*node).smaller) };
        *fresh20 = t;
        let fresh21 = unsafe { &mut ((*t).larger) };
        *fresh21 = 0 as *mut Curl_tree;
    }
    (unsafe { (*node).key = i });
    let fresh22 = unsafe { &mut ((*node).samen) };
    *fresh22 = node;
    let fresh23 = unsafe { &mut ((*node).samep) };
    *fresh23 = node;
    return node;
}
#[no_mangle]
pub extern "C" fn Curl_splaygetbest(
    mut i: curltime,
    mut t: *mut Curl_tree,
    mut removed: *mut *mut Curl_tree,
) -> *mut Curl_tree {
    static mut tv_zero: curltime = {
        let mut init = curltime {
            tv_sec: 0 as i32 as time_t,
            tv_usec: 0 as i32,
        };
        init
    };
    let mut x: *mut Curl_tree = 0 as *mut Curl_tree;
    if t.is_null() {
        (unsafe { *removed = 0 as *mut Curl_tree });
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
        (unsafe { *removed = 0 as *mut Curl_tree });
        return t;
    }
    x = unsafe { (*t).samen };
    if x != t {
        (unsafe { (*x).key = (*t).key });
        let fresh24 = unsafe { &mut ((*x).larger) };
        *fresh24 = unsafe { (*t).larger };
        let fresh25 = unsafe { &mut ((*x).smaller) };
        *fresh25 = unsafe { (*t).smaller };
        let fresh26 = unsafe { &mut ((*x).samep) };
        *fresh26 = unsafe { (*t).samep };
        let fresh27 = unsafe { &mut ((*(*t).samep).samen) };
        *fresh27 = x;
        (unsafe { *removed = t });
        return x;
    }
    x = unsafe { (*t).larger };
    (unsafe { *removed = t });
    return x;
}
#[no_mangle]
pub extern "C" fn Curl_splayremove(
    mut t: *mut Curl_tree,
    mut removenode: *mut Curl_tree,
    mut newroot: *mut *mut Curl_tree,
) -> i32 {
    static mut KEY_NOTUSED: curltime = {
        let mut init = curltime {
            tv_sec: -(1 as i32) as time_t,
            tv_usec: -(1 as i32) as u32 as i32,
        };
        init
    };
    let mut x: *mut Curl_tree = 0 as *mut Curl_tree;
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
        let fresh28 = unsafe { &mut ((*(*removenode).samep).samen) };
        *fresh28 = unsafe { (*removenode).samen };
        let fresh29 = unsafe { &mut ((*(*removenode).samen).samep) };
        *fresh29 = unsafe { (*removenode).samep };
        let fresh30 = unsafe { &mut ((*removenode).samen) };
        *fresh30 = removenode;
        (unsafe { *newroot = t });
        return 0 as i32;
    }
    t = Curl_splay(unsafe { (*removenode).key }, t);
    if t != removenode {
        return 2 as i32;
    }
    x = unsafe { (*t).samen };
    if x != t {
        (unsafe { (*x).key = (*t).key });
        let fresh31 = unsafe { &mut ((*x).larger) };
        *fresh31 = unsafe { (*t).larger };
        let fresh32 = unsafe { &mut ((*x).smaller) };
        *fresh32 = unsafe { (*t).smaller };
        let fresh33 = unsafe { &mut ((*x).samep) };
        *fresh33 = unsafe { (*t).samep };
        let fresh34 = unsafe { &mut ((*(*t).samep).samen) };
        *fresh34 = x;
    } else if (unsafe { (*t).smaller }).is_null() {
        x = unsafe { (*t).larger };
    } else {
        x = Curl_splay(unsafe { (*removenode).key }, unsafe { (*t).smaller });
        let fresh35 = unsafe { &mut ((*x).larger) };
        *fresh35 = unsafe { (*t).larger };
    }
    (unsafe { *newroot = x });
    return 0 as i32;
}
