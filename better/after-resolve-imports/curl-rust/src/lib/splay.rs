use ::libc;
pub type __time_t = crate::src::lib::altsvc::__time_t;
pub type time_t = crate::src::lib::altsvc::time_t;
// #[derive(Copy, Clone)]

pub type curltime = crate::src::lib::altsvc::curltime;
// #[derive(Copy, Clone)]

pub type Curl_tree = crate::src::lib::altsvc::Curl_tree;
#[no_mangle]
pub unsafe extern "C" fn Curl_splay(
    mut i: curltime,
    mut t: *mut Curl_tree,
) -> *mut Curl_tree {
    let mut N: Curl_tree = Curl_tree {
        smaller: 0 as *mut Curl_tree,
        larger: 0 as *mut Curl_tree,
        samen: 0 as *mut Curl_tree,
        samep: 0 as *mut Curl_tree,
        key: curltime { tv_sec: 0, tv_usec: 0 },
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
        let mut comp: i64 = (if i.tv_sec < (*t).key.tv_sec {
            -(1 as i32)
        } else if i.tv_sec > (*t).key.tv_sec {
            1 as i32
        } else if i.tv_usec < (*t).key.tv_usec {
            -(1 as i32)
        } else if i.tv_usec > (*t).key.tv_usec {
            1 as i32
        } else {
            0 as i32
        }) as i64;
        if comp < 0 as i32 as i64 {
            if ((*t).smaller).is_null() {
                break;
            }
            if (if i.tv_sec < (*(*t).smaller).key.tv_sec {
                -(1 as i32)
            } else {
                (if i.tv_sec > (*(*t).smaller).key.tv_sec {
                    1 as i32
                } else {
                    (if i.tv_usec < (*(*t).smaller).key.tv_usec {
                        -(1 as i32)
                    } else {
                        (if i.tv_usec > (*(*t).smaller).key.tv_usec {
                            1 as i32
                        } else {
                            0 as i32
                        })
                    })
                })
            }) < 0 as i32
            {
                y = (*t).smaller;
                let fresh0 = &mut ((*t).smaller);
                *fresh0 = (*y).larger;
                let fresh1 = &mut ((*y).larger);
                *fresh1 = t;
                t = y;
                if ((*t).smaller).is_null() {
                    break;
                }
            }
            let fresh2 = &mut ((*r).smaller);
            *fresh2 = t;
            r = t;
            t = (*t).smaller;
        } else {
            if !(comp > 0 as i32 as i64) {
                break;
            }
            if ((*t).larger).is_null() {
                break;
            }
            if (if i.tv_sec < (*(*t).larger).key.tv_sec {
                -(1 as i32)
            } else {
                (if i.tv_sec > (*(*t).larger).key.tv_sec {
                    1 as i32
                } else {
                    (if i.tv_usec < (*(*t).larger).key.tv_usec {
                        -(1 as i32)
                    } else {
                        (if i.tv_usec > (*(*t).larger).key.tv_usec {
                            1 as i32
                        } else {
                            0 as i32
                        })
                    })
                })
            }) > 0 as i32
            {
                y = (*t).larger;
                let fresh3 = &mut ((*t).larger);
                *fresh3 = (*y).smaller;
                let fresh4 = &mut ((*y).smaller);
                *fresh4 = t;
                t = y;
                if ((*t).larger).is_null() {
                    break;
                }
            }
            let fresh5 = &mut ((*l).larger);
            *fresh5 = t;
            l = t;
            t = (*t).larger;
        }
    }
    let fresh6 = &mut ((*l).larger);
    *fresh6 = (*t).smaller;
    let fresh7 = &mut ((*r).smaller);
    *fresh7 = (*t).larger;
    let fresh8 = &mut ((*t).smaller);
    *fresh8 = N.larger;
    let fresh9 = &mut ((*t).larger);
    *fresh9 = N.smaller;
    return t;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_splayinsert(
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
        if (if i.tv_sec < (*t).key.tv_sec {
            -(1 as i32)
        } else {
            (if i.tv_sec > (*t).key.tv_sec {
                1 as i32
            } else {
                (if i.tv_usec < (*t).key.tv_usec {
                    -(1 as i32)
                } else {
                    (if i.tv_usec > (*t).key.tv_usec {
                        1 as i32
                    } else {
                        0 as i32
                    })
                })
            })
        }) == 0 as i32
        {
            (*node).key = KEY_NOTUSED;
            let fresh10 = &mut ((*node).samen);
            *fresh10 = t;
            let fresh11 = &mut ((*node).samep);
            *fresh11 = (*t).samep;
            let fresh12 = &mut ((*(*t).samep).samen);
            *fresh12 = node;
            let fresh13 = &mut ((*t).samep);
            *fresh13 = node;
            return t;
        }
    }
    if t.is_null() {
        let fresh14 = &mut ((*node).larger);
        *fresh14 = 0 as *mut Curl_tree;
        let fresh15 = &mut ((*node).smaller);
        *fresh15 = *fresh14;
    } else if (if i.tv_sec < (*t).key.tv_sec {
            -(1 as i32)
        } else {
            (if i.tv_sec > (*t).key.tv_sec {
                1 as i32
            } else {
                (if i.tv_usec < (*t).key.tv_usec {
                    -(1 as i32)
                } else {
                    (if i.tv_usec > (*t).key.tv_usec {
                        1 as i32
                    } else {
                        0 as i32
                    })
                })
            })
        }) < 0 as i32
        {
        let fresh16 = &mut ((*node).smaller);
        *fresh16 = (*t).smaller;
        let fresh17 = &mut ((*node).larger);
        *fresh17 = t;
        let fresh18 = &mut ((*t).smaller);
        *fresh18 = 0 as *mut Curl_tree;
    } else {
        let fresh19 = &mut ((*node).larger);
        *fresh19 = (*t).larger;
        let fresh20 = &mut ((*node).smaller);
        *fresh20 = t;
        let fresh21 = &mut ((*t).larger);
        *fresh21 = 0 as *mut Curl_tree;
    }
    (*node).key = i;
    let fresh22 = &mut ((*node).samen);
    *fresh22 = node;
    let fresh23 = &mut ((*node).samep);
    *fresh23 = node;
    return node;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_splaygetbest(
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
        *removed = 0 as *mut Curl_tree;
        return 0 as *mut Curl_tree;
    }
    t = Curl_splay(tv_zero, t);
    if (if i.tv_sec < (*t).key.tv_sec {
        -(1 as i32)
    } else {
        (if i.tv_sec > (*t).key.tv_sec {
            1 as i32
        } else {
            (if i.tv_usec < (*t).key.tv_usec {
                -(1 as i32)
            } else {
                (if i.tv_usec > (*t).key.tv_usec {
                    1 as i32
                } else {
                    0 as i32
                })
            })
        })
    }) < 0 as i32
    {
        *removed = 0 as *mut Curl_tree;
        return t;
    }
    x = (*t).samen;
    if x != t {
        (*x).key = (*t).key;
        let fresh24 = &mut ((*x).larger);
        *fresh24 = (*t).larger;
        let fresh25 = &mut ((*x).smaller);
        *fresh25 = (*t).smaller;
        let fresh26 = &mut ((*x).samep);
        *fresh26 = (*t).samep;
        let fresh27 = &mut ((*(*t).samep).samen);
        *fresh27 = x;
        *removed = t;
        return x;
    }
    x = (*t).larger;
    *removed = t;
    return x;
}
#[no_mangle]
pub unsafe extern "C" fn Curl_splayremove(
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
    if (if KEY_NOTUSED.tv_sec < (*removenode).key.tv_sec {
        -(1 as i32)
    } else {
        (if KEY_NOTUSED.tv_sec > (*removenode).key.tv_sec {
            1 as i32
        } else {
            (if KEY_NOTUSED.tv_usec < (*removenode).key.tv_usec {
                -(1 as i32)
            } else {
                (if KEY_NOTUSED.tv_usec > (*removenode).key.tv_usec {
                    1 as i32
                } else {
                    0 as i32
                })
            })
        })
    }) == 0 as i32
    {
        if (*removenode).samen == removenode {
            return 3 as i32;
        }
        let fresh28 = &mut ((*(*removenode).samep).samen);
        *fresh28 = (*removenode).samen;
        let fresh29 = &mut ((*(*removenode).samen).samep);
        *fresh29 = (*removenode).samep;
        let fresh30 = &mut ((*removenode).samen);
        *fresh30 = removenode;
        *newroot = t;
        return 0 as i32;
    }
    t = Curl_splay((*removenode).key, t);
    if t != removenode {
        return 2 as i32;
    }
    x = (*t).samen;
    if x != t {
        (*x).key = (*t).key;
        let fresh31 = &mut ((*x).larger);
        *fresh31 = (*t).larger;
        let fresh32 = &mut ((*x).smaller);
        *fresh32 = (*t).smaller;
        let fresh33 = &mut ((*x).samep);
        *fresh33 = (*t).samep;
        let fresh34 = &mut ((*(*t).samep).samen);
        *fresh34 = x;
    } else if ((*t).smaller).is_null() {
        x = (*t).larger;
    } else {
        x = Curl_splay((*removenode).key, (*t).smaller);
        let fresh35 = &mut ((*x).larger);
        *fresh35 = (*t).larger;
    }
    *newroot = x;
    return 0 as i32;
}
