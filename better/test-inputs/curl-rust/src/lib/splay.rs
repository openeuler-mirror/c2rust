use ::libc;
pub type __time_t = libc::c_long;
pub type time_t = __time_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curltime {
    pub tv_sec: time_t,
    pub tv_usec: libc::c_int,
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
        let mut comp: libc::c_long = (if i.tv_sec < (*t).key.tv_sec {
            -(1 as libc::c_int)
        } else if i.tv_sec > (*t).key.tv_sec {
            1 as libc::c_int
        } else if i.tv_usec < (*t).key.tv_usec {
            -(1 as libc::c_int)
        } else if i.tv_usec > (*t).key.tv_usec {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        }) as libc::c_long;
        if comp < 0 as libc::c_int as libc::c_long {
            if ((*t).smaller).is_null() {
                break;
            }
            if (if i.tv_sec < (*(*t).smaller).key.tv_sec {
                -(1 as libc::c_int)
            } else {
                (if i.tv_sec > (*(*t).smaller).key.tv_sec {
                    1 as libc::c_int
                } else {
                    (if i.tv_usec < (*(*t).smaller).key.tv_usec {
                        -(1 as libc::c_int)
                    } else {
                        (if i.tv_usec > (*(*t).smaller).key.tv_usec {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        })
                    })
                })
            }) < 0 as libc::c_int
            {
                y = (*t).smaller;
                let ref mut fresh0 = (*t).smaller;
                *fresh0 = (*y).larger;
                let ref mut fresh1 = (*y).larger;
                *fresh1 = t;
                t = y;
                if ((*t).smaller).is_null() {
                    break;
                }
            }
            let ref mut fresh2 = (*r).smaller;
            *fresh2 = t;
            r = t;
            t = (*t).smaller;
        } else {
            if !(comp > 0 as libc::c_int as libc::c_long) {
                break;
            }
            if ((*t).larger).is_null() {
                break;
            }
            if (if i.tv_sec < (*(*t).larger).key.tv_sec {
                -(1 as libc::c_int)
            } else {
                (if i.tv_sec > (*(*t).larger).key.tv_sec {
                    1 as libc::c_int
                } else {
                    (if i.tv_usec < (*(*t).larger).key.tv_usec {
                        -(1 as libc::c_int)
                    } else {
                        (if i.tv_usec > (*(*t).larger).key.tv_usec {
                            1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        })
                    })
                })
            }) > 0 as libc::c_int
            {
                y = (*t).larger;
                let ref mut fresh3 = (*t).larger;
                *fresh3 = (*y).smaller;
                let ref mut fresh4 = (*y).smaller;
                *fresh4 = t;
                t = y;
                if ((*t).larger).is_null() {
                    break;
                }
            }
            let ref mut fresh5 = (*l).larger;
            *fresh5 = t;
            l = t;
            t = (*t).larger;
        }
    }
    let ref mut fresh6 = (*l).larger;
    *fresh6 = (*t).smaller;
    let ref mut fresh7 = (*r).smaller;
    *fresh7 = (*t).larger;
    let ref mut fresh8 = (*t).smaller;
    *fresh8 = N.larger;
    let ref mut fresh9 = (*t).larger;
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
            tv_sec: -(1 as libc::c_int) as time_t,
            tv_usec: -(1 as libc::c_int) as libc::c_uint as libc::c_int,
        };
        init
    };
    if node.is_null() {
        return t;
    }
    if !t.is_null() {
        t = Curl_splay(i, t);
        if (if i.tv_sec < (*t).key.tv_sec {
            -(1 as libc::c_int)
        } else {
            (if i.tv_sec > (*t).key.tv_sec {
                1 as libc::c_int
            } else {
                (if i.tv_usec < (*t).key.tv_usec {
                    -(1 as libc::c_int)
                } else {
                    (if i.tv_usec > (*t).key.tv_usec {
                        1 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })
                })
            })
        }) == 0 as libc::c_int
        {
            (*node).key = KEY_NOTUSED;
            let ref mut fresh10 = (*node).samen;
            *fresh10 = t;
            let ref mut fresh11 = (*node).samep;
            *fresh11 = (*t).samep;
            let ref mut fresh12 = (*(*t).samep).samen;
            *fresh12 = node;
            let ref mut fresh13 = (*t).samep;
            *fresh13 = node;
            return t;
        }
    }
    if t.is_null() {
        let ref mut fresh14 = (*node).larger;
        *fresh14 = 0 as *mut Curl_tree;
        let ref mut fresh15 = (*node).smaller;
        *fresh15 = *fresh14;
    } else if (if i.tv_sec < (*t).key.tv_sec {
            -(1 as libc::c_int)
        } else {
            (if i.tv_sec > (*t).key.tv_sec {
                1 as libc::c_int
            } else {
                (if i.tv_usec < (*t).key.tv_usec {
                    -(1 as libc::c_int)
                } else {
                    (if i.tv_usec > (*t).key.tv_usec {
                        1 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })
                })
            })
        }) < 0 as libc::c_int
        {
        let ref mut fresh16 = (*node).smaller;
        *fresh16 = (*t).smaller;
        let ref mut fresh17 = (*node).larger;
        *fresh17 = t;
        let ref mut fresh18 = (*t).smaller;
        *fresh18 = 0 as *mut Curl_tree;
    } else {
        let ref mut fresh19 = (*node).larger;
        *fresh19 = (*t).larger;
        let ref mut fresh20 = (*node).smaller;
        *fresh20 = t;
        let ref mut fresh21 = (*t).larger;
        *fresh21 = 0 as *mut Curl_tree;
    }
    (*node).key = i;
    let ref mut fresh22 = (*node).samen;
    *fresh22 = node;
    let ref mut fresh23 = (*node).samep;
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
            tv_sec: 0 as libc::c_int as time_t,
            tv_usec: 0 as libc::c_int,
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
        -(1 as libc::c_int)
    } else {
        (if i.tv_sec > (*t).key.tv_sec {
            1 as libc::c_int
        } else {
            (if i.tv_usec < (*t).key.tv_usec {
                -(1 as libc::c_int)
            } else {
                (if i.tv_usec > (*t).key.tv_usec {
                    1 as libc::c_int
                } else {
                    0 as libc::c_int
                })
            })
        })
    }) < 0 as libc::c_int
    {
        *removed = 0 as *mut Curl_tree;
        return t;
    }
    x = (*t).samen;
    if x != t {
        (*x).key = (*t).key;
        let ref mut fresh24 = (*x).larger;
        *fresh24 = (*t).larger;
        let ref mut fresh25 = (*x).smaller;
        *fresh25 = (*t).smaller;
        let ref mut fresh26 = (*x).samep;
        *fresh26 = (*t).samep;
        let ref mut fresh27 = (*(*t).samep).samen;
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
) -> libc::c_int {
    static mut KEY_NOTUSED: curltime = {
        let mut init = curltime {
            tv_sec: -(1 as libc::c_int) as time_t,
            tv_usec: -(1 as libc::c_int) as libc::c_uint as libc::c_int,
        };
        init
    };
    let mut x: *mut Curl_tree = 0 as *mut Curl_tree;
    if t.is_null() || removenode.is_null() {
        return 1 as libc::c_int;
    }
    if (if KEY_NOTUSED.tv_sec < (*removenode).key.tv_sec {
        -(1 as libc::c_int)
    } else {
        (if KEY_NOTUSED.tv_sec > (*removenode).key.tv_sec {
            1 as libc::c_int
        } else {
            (if KEY_NOTUSED.tv_usec < (*removenode).key.tv_usec {
                -(1 as libc::c_int)
            } else {
                (if KEY_NOTUSED.tv_usec > (*removenode).key.tv_usec {
                    1 as libc::c_int
                } else {
                    0 as libc::c_int
                })
            })
        })
    }) == 0 as libc::c_int
    {
        if (*removenode).samen == removenode {
            return 3 as libc::c_int;
        }
        let ref mut fresh28 = (*(*removenode).samep).samen;
        *fresh28 = (*removenode).samen;
        let ref mut fresh29 = (*(*removenode).samen).samep;
        *fresh29 = (*removenode).samep;
        let ref mut fresh30 = (*removenode).samen;
        *fresh30 = removenode;
        *newroot = t;
        return 0 as libc::c_int;
    }
    t = Curl_splay((*removenode).key, t);
    if t != removenode {
        return 2 as libc::c_int;
    }
    x = (*t).samen;
    if x != t {
        (*x).key = (*t).key;
        let ref mut fresh31 = (*x).larger;
        *fresh31 = (*t).larger;
        let ref mut fresh32 = (*x).smaller;
        *fresh32 = (*t).smaller;
        let ref mut fresh33 = (*x).samep;
        *fresh33 = (*t).samep;
        let ref mut fresh34 = (*(*t).samep).samen;
        *fresh34 = x;
    } else if ((*t).smaller).is_null() {
        x = (*t).larger;
    } else {
        x = Curl_splay((*removenode).key, (*t).smaller);
        let ref mut fresh35 = (*x).larger;
        *fresh35 = (*t).larger;
    }
    *newroot = x;
    return 0 as libc::c_int;
}
