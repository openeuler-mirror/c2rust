use :: libc;
extern "C" {
    pub type _xmlCatalog;
    static mut stdin: *mut crate::src::tree::_IO_FILE;
    static mut stdout: *mut crate::src::tree::_IO_FILE;
    static mut stderr: *mut crate::src::tree::_IO_FILE;
    fn remove(__filename: *const i8) -> i32;
    fn fclose(__stream: *mut crate::src::tree::_IO_FILE) -> i32;
    fn fflush(__stream: *mut crate::src::tree::_IO_FILE) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut crate::src::tree::_IO_FILE;
    fn fprintf(_: *mut crate::src::tree::_IO_FILE, _: *const i8, _: ...) -> i32;
    fn xmlCheckVersion(version: i32);
    fn fgets(__s: *mut i8, __n: i32, __stream: *mut crate::src::tree::_IO_FILE) -> *mut i8;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn strlen(_: *const i8) -> u64;
    fn malloc(_: u64) -> *mut core::ffi::c_void;
    fn free(__ptr: *mut core::ffi::c_void);
    fn xmlCleanupParser();
    static mut xmlFree: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
    fn xmlNewCatalog(sgml_0: i32) -> *mut crate::src::xmlcatalog::_xmlCatalog;
    fn xmlLoadSGMLSuperCatalog(filename_0: *const i8) -> *mut crate::src::xmlcatalog::_xmlCatalog;
    fn xmlACatalogAdd(
        catal: *mut crate::src::xmlcatalog::_xmlCatalog,
        type_0: *const u8,
        orig: *const u8,
        replace: *const u8,
    ) -> i32;
    fn xmlACatalogRemove(catal: *mut crate::src::xmlcatalog::_xmlCatalog, value: *const u8) -> i32;
    fn xmlACatalogDump(
        catal: *mut crate::src::xmlcatalog::_xmlCatalog,
        out: *mut crate::src::tree::_IO_FILE,
    );
    fn xmlCatalogIsEmpty(catal: *mut crate::src::xmlcatalog::_xmlCatalog) -> i32;
    fn xmlInitializeCatalog();
    fn xmlLoadCatalog(filename_0: *const i8) -> i32;
    fn xmlCatalogDump(out: *mut crate::src::tree::_IO_FILE);
    fn xmlCatalogResolve(pubID: *const u8, sysID: *const u8) -> *mut u8;
    fn xmlCatalogResolveSystem(sysID: *const u8) -> *mut u8;
    fn xmlCatalogResolvePublic(pubID: *const u8) -> *mut u8;
    fn xmlCatalogResolveURI(URI: *const u8) -> *mut u8;
    fn xmlCatalogAdd(type_0: *const u8, orig: *const u8, replace: *const u8) -> i32;
    fn xmlCatalogRemove(value: *const u8) -> i32;
    fn xmlCatalogConvert() -> i32;
    fn xmlCatalogSetDebug(level: i32) -> i32;
}
pub use crate::src::uri::xmlFreeURI;
pub use crate::src::uri::xmlParseURI;
pub use crate::src::xmllint::_IO_marker;
pub use crate::src::xmlmemory::_IO_wide_data;
pub use crate::src::xmlmemory::xmlMemoryDump;
pub use crate::src::xmlsave::_IO_codecvt;
pub type xmlChar = u8;
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type _IO_FILE = crate::src::tree::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::tree::_IO_FILE;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type _xmlURI = crate::src::uri::_xmlURI;
pub type xmlURI = crate::src::uri::_xmlURI;
pub type xmlURIPtr = *mut crate::src::uri::_xmlURI;
pub type xmlCatalog = crate::src::xmlcatalog::_xmlCatalog;
pub type xmlCatalogPtr = *mut crate::src::xmlcatalog::_xmlCatalog;
static mut shell: i32 = 0 as i32;
static mut sgml: i32 = 0 as i32;
static mut noout: i32 = 0 as i32;
static mut create: i32 = 0 as i32;
static mut add: i32 = 0 as i32;
static mut del: i32 = 0 as i32;
static mut convert: i32 = 0 as i32;
static mut no_super_update: i32 = 0 as i32;
static mut verbose: i32 = 0 as i32;
static mut filename: *mut i8 = 0 as *const i8 as *mut i8;
extern "C" fn xmlShellReadline(mut prompt: *const i8) -> *mut i8 {
    let mut line_read: [i8; 501] = [0; 501];
    let mut ret: *mut i8 = 0 as *mut i8;
    let mut len: i32 = 0;
    if !prompt.is_null() {
        (unsafe { fprintf(stdout, b"%s\0" as *const u8 as *const i8, prompt) });
    }
    (unsafe { fflush(stdout) });
    if (unsafe { fgets(line_read.as_mut_ptr(), 500 as i32, stdin) }).is_null() {
        return 0 as *mut i8;
    }
    line_read[500 as i32 as usize] = 0 as i32 as i8;
    len = (unsafe { strlen(line_read.as_mut_ptr()) }) as i32;
    ret = (unsafe { malloc((len + 1 as i32) as u64) }) as *mut i8;
    if !ret.is_null() {
        (unsafe {
            memcpy(
                ret as *mut libc::c_void,
                line_read.as_mut_ptr() as *const libc::c_void,
                (len + 1 as i32) as u64,
            )
        });
    }
    return ret;
}
extern "C" fn usershell() {
    let mut cmdline: *mut i8 = 0 as *mut i8;
    let mut cur: *mut i8 = 0 as *mut i8;
    let mut nbargs: i32 = 0;
    let mut command: [i8; 100] = [0; 100];
    let mut arg: [i8; 400] = [0; 400];
    let mut argv: [*mut i8; 20] = [0 as *mut i8; 20];
    let mut i: i32 = 0;
    let mut ret: i32 = 0;
    let mut ans: *mut u8 = 0 as *mut xmlChar;
    loop {
        cmdline = xmlShellReadline(b"> \0" as *const u8 as *const i8);
        if cmdline.is_null() {
            return;
        }
        cur = cmdline;
        nbargs = 0 as i32;
        while (unsafe { *cur }) as i32 == ' ' as i32 || (unsafe { *cur }) as i32 == '\t' as i32 {
            cur = unsafe { cur.offset(1) };
        }
        i = 0 as i32;
        while (unsafe { *cur }) as i32 != ' ' as i32
            && (unsafe { *cur }) as i32 != '\t' as i32
            && (unsafe { *cur }) as i32 != '\n' as i32
            && (unsafe { *cur }) as i32 != '\r' as i32
        {
            if (unsafe { *cur }) as i32 == 0 as i32 {
                break;
            }
            let mut fresh0 = cur;
            cur = unsafe { cur.offset(1) };
            let mut fresh1 = i;
            i = i + 1;
            command[fresh1 as usize] = unsafe { *fresh0 };
        }
        command[i as usize] = 0 as i32 as i8;
        if i == 0 as i32 {
            (unsafe { free(cmdline as *mut libc::c_void) });
        } else {
            (unsafe {
                memset(
                    arg.as_mut_ptr() as *mut libc::c_void,
                    0 as i32,
                    ::std::mem::size_of::<[i8; 400]>() as u64,
                )
            });
            while (unsafe { *cur }) as i32 == ' ' as i32 || (unsafe { *cur }) as i32 == '\t' as i32
            {
                cur = unsafe { cur.offset(1) };
            }
            i = 0 as i32;
            while (unsafe { *cur }) as i32 != '\n' as i32
                && (unsafe { *cur }) as i32 != '\r' as i32
                && (unsafe { *cur }) as i32 != 0 as i32
            {
                if (unsafe { *cur }) as i32 == 0 as i32 {
                    break;
                }
                let mut fresh2 = cur;
                cur = unsafe { cur.offset(1) };
                let mut fresh3 = i;
                i = i + 1;
                arg[fresh3 as usize] = unsafe { *fresh2 };
            }
            arg[i as usize] = 0 as i32 as i8;
            i = 0 as i32;
            nbargs = 0 as i32;
            cur = arg.as_mut_ptr();
            (unsafe {
                memset(
                    argv.as_mut_ptr() as *mut libc::c_void,
                    0 as i32,
                    ::std::mem::size_of::<[*mut i8; 20]>() as u64,
                )
            });
            while (unsafe { *cur }) as i32 != 0 as i32 {
                while (unsafe { *cur }) as i32 == ' ' as i32
                    || (unsafe { *cur }) as i32 == '\t' as i32
                {
                    cur = unsafe { cur.offset(1) };
                }
                if (unsafe { *cur }) as i32 == '\'' as i32 {
                    cur = unsafe { cur.offset(1) };
                    argv[i as usize] = cur;
                    while (unsafe { *cur }) as i32 != 0 as i32
                        && (unsafe { *cur }) as i32 != '\'' as i32
                    {
                        cur = unsafe { cur.offset(1) };
                    }
                    if (unsafe { *cur }) as i32 == '\'' as i32 {
                        (unsafe { *cur = 0 as i32 as i8 });
                        nbargs += 1;
                        i += 1;
                        cur = unsafe { cur.offset(1) };
                    }
                } else if (unsafe { *cur }) as i32 == '"' as i32 {
                    cur = unsafe { cur.offset(1) };
                    argv[i as usize] = cur;
                    while (unsafe { *cur }) as i32 != 0 as i32
                        && (unsafe { *cur }) as i32 != '"' as i32
                    {
                        cur = unsafe { cur.offset(1) };
                    }
                    if (unsafe { *cur }) as i32 == '"' as i32 {
                        (unsafe { *cur = 0 as i32 as i8 });
                        nbargs += 1;
                        i += 1;
                        cur = unsafe { cur.offset(1) };
                    }
                } else {
                    argv[i as usize] = cur;
                    while (unsafe { *cur }) as i32 != 0 as i32
                        && (unsafe { *cur }) as i32 != ' ' as i32
                        && (unsafe { *cur }) as i32 != '\t' as i32
                    {
                        cur = unsafe { cur.offset(1) };
                    }
                    (unsafe { *cur = 0 as i32 as i8 });
                    nbargs += 1;
                    i += 1;
                    cur = unsafe { cur.offset(1) };
                }
            }
            if (unsafe { strcmp(command.as_mut_ptr(), b"exit\0" as *const u8 as *const i8) }) == 0
                || (unsafe { strcmp(command.as_mut_ptr(), b"quit\0" as *const u8 as *const i8) })
                    == 0
                || (unsafe { strcmp(command.as_mut_ptr(), b"bye\0" as *const u8 as *const i8) })
                    == 0
            {
                (unsafe { free(cmdline as *mut libc::c_void) });
                break;
            } else {
                if (unsafe { strcmp(command.as_mut_ptr(), b"public\0" as *const u8 as *const i8) })
                    == 0
                {
                    if nbargs != 1 as i32 {
                        (unsafe {
                            printf(b"public requires 1 arguments\n\0" as *const u8 as *const i8)
                        });
                    } else {
                        ans = unsafe {
                            xmlCatalogResolvePublic(argv[0 as i32 as usize] as *const xmlChar)
                        };
                        if ans.is_null() {
                            (unsafe {
                                printf(
                                    b"No entry for PUBLIC %s\n\0" as *const u8 as *const i8,
                                    argv[0 as i32 as usize],
                                )
                            });
                        } else {
                            (unsafe {
                                printf(b"%s\n\0" as *const u8 as *const i8, ans as *mut i8)
                            });
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    ans as *mut libc::c_void,
                                )
                            });
                        }
                    }
                } else if (unsafe {
                    strcmp(command.as_mut_ptr(), b"system\0" as *const u8 as *const i8)
                }) == 0
                {
                    if nbargs != 1 as i32 {
                        (unsafe {
                            printf(b"system requires 1 arguments\n\0" as *const u8 as *const i8)
                        });
                    } else {
                        ans = unsafe {
                            xmlCatalogResolveSystem(argv[0 as i32 as usize] as *const xmlChar)
                        };
                        if ans.is_null() {
                            (unsafe {
                                printf(
                                    b"No entry for SYSTEM %s\n\0" as *const u8 as *const i8,
                                    argv[0 as i32 as usize],
                                )
                            });
                        } else {
                            (unsafe {
                                printf(b"%s\n\0" as *const u8 as *const i8, ans as *mut i8)
                            });
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    ans as *mut libc::c_void,
                                )
                            });
                        }
                    }
                } else if (unsafe {
                    strcmp(command.as_mut_ptr(), b"add\0" as *const u8 as *const i8)
                }) == 0
                {
                    if nbargs != 3 as i32 && nbargs != 2 as i32 {
                        (unsafe {
                            printf(b"add requires 2 or 3 arguments\n\0" as *const u8 as *const i8)
                        });
                    } else {
                        if (argv[2 as i32 as usize]).is_null() {
                            ret = unsafe {
                                xmlCatalogAdd(
                                    argv[0 as i32 as usize] as *mut xmlChar,
                                    0 as *const xmlChar,
                                    argv[1 as i32 as usize] as *mut xmlChar,
                                )
                            };
                        } else {
                            ret = unsafe {
                                xmlCatalogAdd(
                                    argv[0 as i32 as usize] as *mut xmlChar,
                                    argv[1 as i32 as usize] as *mut xmlChar,
                                    argv[2 as i32 as usize] as *mut xmlChar,
                                )
                            };
                        }
                        if ret != 0 as i32 {
                            (unsafe {
                                printf(b"add command failed\n\0" as *const u8 as *const i8)
                            });
                        }
                    }
                } else if (unsafe {
                    strcmp(command.as_mut_ptr(), b"del\0" as *const u8 as *const i8)
                }) == 0
                {
                    if nbargs != 1 as i32 {
                        (unsafe { printf(b"del requires 1\n\0" as *const u8 as *const i8) });
                    } else {
                        ret =
                            unsafe { xmlCatalogRemove(argv[0 as i32 as usize] as *mut xmlChar) };
                        if ret <= 0 as i32 {
                            (unsafe {
                                printf(b"del command failed\n\0" as *const u8 as *const i8)
                            });
                        }
                    }
                } else if (unsafe {
                    strcmp(command.as_mut_ptr(), b"resolve\0" as *const u8 as *const i8)
                }) == 0
                {
                    if nbargs != 2 as i32 {
                        (unsafe {
                            printf(b"resolve requires 2 arguments\n\0" as *const u8 as *const i8)
                        });
                    } else {
                        ans = unsafe {
                            xmlCatalogResolve(
                                argv[0 as i32 as usize] as *mut xmlChar,
                                argv[1 as i32 as usize] as *mut xmlChar,
                            )
                        };
                        if ans.is_null() {
                            (unsafe {
                                printf(
                                    b"Resolver failed to find an answer\n\0" as *const u8
                                        as *const i8,
                                )
                            });
                        } else {
                            (unsafe {
                                printf(b"%s\n\0" as *const u8 as *const i8, ans as *mut i8)
                            });
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    ans as *mut libc::c_void,
                                )
                            });
                        }
                    }
                } else if (unsafe {
                    strcmp(command.as_mut_ptr(), b"dump\0" as *const u8 as *const i8)
                }) == 0
                {
                    if nbargs != 0 as i32 {
                        (unsafe { printf(b"dump has no arguments\n\0" as *const u8 as *const i8) });
                    } else {
                        (unsafe { xmlCatalogDump(stdout) });
                    }
                } else if (unsafe {
                    strcmp(command.as_mut_ptr(), b"debug\0" as *const u8 as *const i8)
                }) == 0
                {
                    if nbargs != 0 as i32 {
                        (unsafe {
                            printf(b"debug has no arguments\n\0" as *const u8 as *const i8)
                        });
                    } else {
                        (unsafe { verbose += 1 });
                        (unsafe { xmlCatalogSetDebug(verbose) });
                    }
                } else if (unsafe {
                    strcmp(command.as_mut_ptr(), b"quiet\0" as *const u8 as *const i8)
                }) == 0
                {
                    if nbargs != 0 as i32 {
                        (unsafe {
                            printf(b"quiet has no arguments\n\0" as *const u8 as *const i8)
                        });
                    } else {
                        if (unsafe { verbose }) > 0 as i32 {
                            (unsafe { verbose -= 1 });
                        }
                        (unsafe { xmlCatalogSetDebug(verbose) });
                    }
                } else {
                    if (unsafe {
                        strcmp(command.as_mut_ptr(), b"help\0" as *const u8 as *const i8)
                    }) != 0
                    {
                        (unsafe {
                            printf(
                                b"Unrecognized command %s\n\0" as *const u8 as *const i8,
                                command.as_mut_ptr(),
                            )
                        });
                    }
                    (unsafe { printf(b"Commands available:\n\0" as *const u8 as *const i8) });
                    (unsafe {
                        printf(
                            b"\tpublic PublicID: make a PUBLIC identifier lookup\n\0" as *const u8
                                as *const i8,
                        )
                    });
                    (unsafe {
                        printf(
                            b"\tsystem SystemID: make a SYSTEM identifier lookup\n\0" as *const u8
                                as *const i8,
                        )
                    });
                    (unsafe {
                        printf(
                            b"\tresolve PublicID SystemID: do a full resolver lookup\n\0"
                                as *const u8 as *const i8,
                        )
                    });
                    (unsafe {
                        printf(
                            b"\tadd 'type' 'orig' 'replace' : add an entry\n\0" as *const u8
                                as *const i8,
                        )
                    });
                    (unsafe {
                        printf(b"\tdel 'values' : remove values\n\0" as *const u8 as *const i8)
                    });
                    (unsafe {
                        printf(
                            b"\tdump: print the current catalog state\n\0" as *const u8
                                as *const i8,
                        )
                    });
                    (unsafe {
                        printf(
                            b"\tdebug: increase the verbosity level\n\0" as *const u8 as *const i8,
                        )
                    });
                    (unsafe {
                        printf(
                            b"\tquiet: decrease the verbosity level\n\0" as *const u8 as *const i8,
                        )
                    });
                    (unsafe { printf(b"\texit:  quit the shell\n\0" as *const u8 as *const i8) });
                }
                (unsafe { free(cmdline as *mut libc::c_void) });
            }
        }
    }
}
extern "C" fn usage(mut name: *const i8) {
    (unsafe {
        printf (b"Usage : %s [options] catalogfile entities...\n\tParse the catalog file (void specification possibly expressed as \"\"\n\tappoints the default system one) and query it for the entities\n\t--sgml : handle SGML Super catalogs for --add and --del\n\t--shell : run a shell allowing interactive queries\n\t--create : create a new catalog\n\t--add 'type' 'orig' 'replace' : add an XML entry\n\t--add 'entry' : add an SGML entry\n\0" as * const u8 as * const i8 , name ,)
    });
    (unsafe {
        printf (b"\t--del 'values' : remove values\n\t--noout: avoid dumping the result on stdout\n\t         used with --add or --del, it saves the catalog changes\n\t         and with --sgml it automatically updates the super catalog\n\t--no-super-update: do not update the SGML super catalog\n\t-v --verbose : provide debug information\n\0" as * const u8 as * const i8 ,)
    });
}
fn main_0(mut argc: i32, mut argv: *mut *mut i8) -> i32 {
    let mut i: i32 = 0;
    let mut ret: i32 = 0;
    let mut exit_value: i32 = 0 as i32;
    if argc <= 1 as i32 {
        usage(unsafe { *argv.offset(0 as i32 as isize) });
        return 1 as i32;
    }
    (unsafe { xmlCheckVersion(21000 as i32) });
    i = 1 as i32;
    while i < argc {
        if (unsafe { strcmp(*argv.offset(i as isize), b"-\0" as *const u8 as *const i8) }) == 0 {
            break;
        }
        if (unsafe { *(*argv.offset(i as isize)).offset(0 as i32 as isize) }) as i32 != '-' as i32 {
            break;
        }
        if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-verbose\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe { strcmp(*argv.offset(i as isize), b"-v\0" as *const u8 as *const i8) }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--verbose\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            (unsafe { verbose += 1 });
            (unsafe { xmlCatalogSetDebug(verbose) });
        } else if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-noout\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--noout\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            (unsafe { noout = 1 as i32 });
        } else if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-shell\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--shell\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            (unsafe { shell += 1 });
            (unsafe { noout = 1 as i32 });
        } else if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-sgml\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--sgml\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            (unsafe { sgml += 1 });
        } else if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-create\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--create\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            (unsafe { create += 1 });
        } else if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-convert\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--convert\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            (unsafe { convert += 1 });
        } else if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-no-super-update\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--no-super-update\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            (unsafe { no_super_update += 1 });
        } else if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-add\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--add\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            if (unsafe { sgml }) != 0 {
                i += 2 as i32;
            } else {
                i += 3 as i32;
            }
            (unsafe { add += 1 });
        } else if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-del\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--del\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            i += 1 as i32;
            (unsafe { del += 1 });
        } else {
            (unsafe {
                fprintf(
                    stderr,
                    b"Unknown option %s\n\0" as *const u8 as *const i8,
                    *argv.offset(i as isize),
                )
            });
            usage(unsafe { *argv.offset(0 as i32 as isize) });
            return 1 as i32;
        }
        i += 1;
    }
    i = 1 as i32;
    while i < argc {
        if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-add\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--add\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            if (unsafe { sgml }) != 0 {
                i += 2 as i32;
            } else {
                i += 3 as i32;
            }
        } else if (unsafe {
            strcmp(
                *argv.offset(i as isize),
                b"-del\0" as *const u8 as *const i8,
            )
        }) == 0
            || (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"--del\0" as *const u8 as *const i8,
                )
            }) == 0
        {
            i += 1 as i32;
            if i == argc || (unsafe { sgml }) != 0 && i + 1 as i32 == argc {
                (unsafe {
                    fprintf(
                        stderr,
                        b"No catalog entry specified to remove from\n\0" as *const u8 as *const i8,
                    )
                });
                usage(unsafe { *argv.offset(0 as i32 as isize) });
                return 1 as i32;
            }
        } else if !((unsafe { *(*argv.offset(i as isize)).offset(0 as i32 as isize) }) as i32
            == '-' as i32)
        {
            if (unsafe { filename }).is_null()
                && (unsafe { *(*argv.offset(i as isize)).offset(0 as i32 as isize) }) as i32
                    == '\u{0}' as i32
            {
                (unsafe { xmlInitializeCatalog() });
            } else {
                (unsafe { filename = *argv.offset(i as isize) });
                ret = unsafe { xmlLoadCatalog(*argv.offset(i as isize)) };
                if ret < 0 as i32 && (unsafe { create }) != 0 {
                    (unsafe {
                        xmlCatalogAdd(
                            b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                            *argv.offset(i as isize) as *mut xmlChar,
                            0 as *const xmlChar,
                        )
                    });
                }
            }
            break;
        }
        i += 1;
    }
    if (unsafe { convert }) != 0 {
        ret = unsafe { xmlCatalogConvert() };
    }
    if (unsafe { add }) != 0 || (unsafe { del }) != 0 {
        i = 1 as i32;
        while i < argc {
            if (unsafe { strcmp(*argv.offset(i as isize), b"-\0" as *const u8 as *const i8) }) == 0
            {
                break;
            }
            if !((unsafe { *(*argv.offset(i as isize)).offset(0 as i32 as isize) }) as i32
                != '-' as i32)
            {
                if !((unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"-add\0" as *const u8 as *const i8,
                    )
                }) != 0
                    && (unsafe {
                        strcmp(
                            *argv.offset(i as isize),
                            b"--add\0" as *const u8 as *const i8,
                        )
                    }) != 0
                    && (unsafe {
                        strcmp(
                            *argv.offset(i as isize),
                            b"-del\0" as *const u8 as *const i8,
                        )
                    }) != 0
                    && (unsafe {
                        strcmp(
                            *argv.offset(i as isize),
                            b"--del\0" as *const u8 as *const i8,
                        )
                    }) != 0)
                {
                    if (unsafe { sgml }) != 0 {
                        let mut catal: *mut crate::src::xmlcatalog::_xmlCatalog =
                            0 as xmlCatalogPtr;
                        let mut super_0: *mut crate::src::xmlcatalog::_xmlCatalog =
                            0 as xmlCatalogPtr;
                        catal = unsafe {
                            xmlLoadSGMLSuperCatalog(*argv.offset((i + 1 as i32) as isize))
                        };
                        if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-add\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--add\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            if catal.is_null() {
                                catal = unsafe { xmlNewCatalog(1 as i32) };
                            }
                            (unsafe {
                                xmlACatalogAdd(
                                    catal,
                                    b"CATALOG\0" as *const u8 as *const i8 as *mut xmlChar,
                                    *argv.offset((i + 2 as i32) as isize) as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            });
                            if (unsafe { no_super_update }) == 0 {
                                super_0 = unsafe {
                                    xmlLoadSGMLSuperCatalog(
                                        b"/usr/local/etc/sgml/catalog\0" as *const u8 as *const i8,
                                    )
                                };
                                if super_0.is_null() {
                                    super_0 = unsafe { xmlNewCatalog(1 as i32) };
                                }
                                (unsafe {
                                    xmlACatalogAdd(
                                        super_0,
                                        b"CATALOG\0" as *const u8 as *const i8 as *mut xmlChar,
                                        *argv.offset((i + 1 as i32) as isize) as *mut xmlChar,
                                        0 as *const xmlChar,
                                    )
                                });
                            }
                        } else {
                            if !catal.is_null() {
                                ret = unsafe {
                                    xmlACatalogRemove(
                                        catal,
                                        *argv.offset((i + 2 as i32) as isize) as *mut xmlChar,
                                    )
                                };
                            } else {
                                ret = -(1 as i32);
                            }
                            if ret < 0 as i32 {
                                (unsafe {
                                    fprintf(
                                        stderr,
                                        b"Failed to remove entry from %s\n\0" as *const u8
                                            as *const i8,
                                        *argv.offset((i + 1 as i32) as isize),
                                    )
                                });
                                exit_value = 1 as i32;
                            }
                            if (unsafe { no_super_update }) == 0
                                && (unsafe { noout }) != 0
                                && !catal.is_null()
                                && (unsafe { xmlCatalogIsEmpty(catal) }) != 0
                            {
                                super_0 = unsafe {
                                    xmlLoadSGMLSuperCatalog(
                                        b"/usr/local/etc/sgml/catalog\0" as *const u8 as *const i8,
                                    )
                                };
                                if !super_0.is_null() {
                                    ret = unsafe {
                                        xmlACatalogRemove(
                                            super_0,
                                            *argv.offset((i + 1 as i32) as isize) as *mut xmlChar,
                                        )
                                    };
                                    if ret < 0 as i32 {
                                        (unsafe {
                                            fprintf(
                                                stderr,
                                                b"Failed to remove entry from %s\n\0" as *const u8
                                                    as *const i8,
                                                b"/usr/local/etc/sgml/catalog\0" as *const u8
                                                    as *const i8,
                                            )
                                        });
                                        exit_value = 1 as i32;
                                    }
                                }
                            }
                        }
                        if (unsafe { noout }) != 0 {
                            let mut out: *mut crate::src::tree::_IO_FILE = 0 as *mut FILE;
                            if (unsafe { xmlCatalogIsEmpty(catal) }) != 0 {
                                (unsafe { remove(*argv.offset((i + 1 as i32) as isize)) });
                            } else {
                                out = unsafe {
                                    fopen(
                                        *argv.offset((i + 1 as i32) as isize),
                                        b"w\0" as *const u8 as *const i8,
                                    )
                                };
                                if out.is_null() {
                                    (unsafe {
                                        fprintf(
                                            stderr,
                                            b"could not open %s for saving\n\0" as *const u8
                                                as *const i8,
                                            *argv.offset((i + 1 as i32) as isize),
                                        )
                                    });
                                    exit_value = 2 as i32;
                                    (unsafe { noout = 0 as i32 });
                                } else {
                                    (unsafe { xmlACatalogDump(catal, out) });
                                    (unsafe { fclose(out) });
                                }
                            }
                            if (unsafe { no_super_update }) == 0 && !super_0.is_null() {
                                if (unsafe { xmlCatalogIsEmpty(super_0) }) != 0 {
                                    (unsafe {
                                        remove(
                                            b"/usr/local/etc/sgml/catalog\0" as *const u8
                                                as *const i8,
                                        )
                                    });
                                } else {
                                    out = unsafe {
                                        fopen(
                                            b"/usr/local/etc/sgml/catalog\0" as *const u8
                                                as *const i8,
                                            b"w\0" as *const u8 as *const i8,
                                        )
                                    };
                                    if out.is_null() {
                                        (unsafe {
                                            fprintf(
                                                stderr,
                                                b"could not open %s for saving\n\0" as *const u8
                                                    as *const i8,
                                                b"/usr/local/etc/sgml/catalog\0" as *const u8
                                                    as *const i8,
                                            )
                                        });
                                        exit_value = 2 as i32;
                                        (unsafe { noout = 0 as i32 });
                                    } else {
                                        (unsafe { xmlACatalogDump(super_0, out) });
                                        (unsafe { fclose(out) });
                                    }
                                }
                            }
                        } else {
                            (unsafe { xmlACatalogDump(catal, stdout) });
                        }
                        i += 2 as i32;
                    } else if (unsafe {
                        strcmp(
                            *argv.offset(i as isize),
                            b"-add\0" as *const u8 as *const i8,
                        )
                    }) == 0
                        || (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"--add\0" as *const u8 as *const i8,
                            )
                        }) == 0
                    {
                        if (unsafe { *argv.offset((i + 3 as i32) as isize) }).is_null()
                            || (unsafe {
                                *(*argv.offset((i + 3 as i32) as isize)).offset(0 as i32 as isize)
                            }) as i32
                                == 0 as i32
                        {
                            ret = unsafe {
                                xmlCatalogAdd(
                                    *argv.offset((i + 1 as i32) as isize) as *mut xmlChar,
                                    0 as *const xmlChar,
                                    *argv.offset((i + 2 as i32) as isize) as *mut xmlChar,
                                )
                            };
                        } else {
                            ret = unsafe {
                                xmlCatalogAdd(
                                    *argv.offset((i + 1 as i32) as isize) as *mut xmlChar,
                                    *argv.offset((i + 2 as i32) as isize) as *mut xmlChar,
                                    *argv.offset((i + 3 as i32) as isize) as *mut xmlChar,
                                )
                            };
                        }
                        if ret != 0 as i32 {
                            (unsafe {
                                printf(b"add command failed\n\0" as *const u8 as *const i8)
                            });
                            exit_value = 3 as i32;
                        }
                        i += 3 as i32;
                    } else if (unsafe {
                        strcmp(
                            *argv.offset(i as isize),
                            b"-del\0" as *const u8 as *const i8,
                        )
                    }) == 0
                        || (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"--del\0" as *const u8 as *const i8,
                            )
                        }) == 0
                    {
                        ret = unsafe {
                            xmlCatalogRemove(*argv.offset((i + 1 as i32) as isize) as *mut xmlChar)
                        };
                        if ret < 0 as i32 {
                            (unsafe {
                                fprintf(
                                    stderr,
                                    b"Failed to remove entry %s\n\0" as *const u8 as *const i8,
                                    *argv.offset((i + 1 as i32) as isize),
                                )
                            });
                            exit_value = 1 as i32;
                        }
                        i += 1 as i32;
                    }
                }
            }
            i += 1;
        }
    } else if (unsafe { shell }) != 0 {
        usershell();
    } else {
        i += 1;
        while i < argc {
            let mut uri: *mut crate::src::uri::_xmlURI = 0 as *mut xmlURI;
            let mut ans: *mut u8 = 0 as *mut xmlChar;
            uri = xmlParseURI(unsafe { *argv.offset(i as isize) });
            if uri.is_null() {
                ans = unsafe {
                    xmlCatalogResolvePublic(*argv.offset(i as isize) as *const xmlChar)
                };
                if ans.is_null() {
                    (unsafe {
                        printf(
                            b"No entry for PUBLIC %s\n\0" as *const u8 as *const i8,
                            *argv.offset(i as isize),
                        )
                    });
                    exit_value = 4 as i32;
                } else {
                    (unsafe { printf(b"%s\n\0" as *const u8 as *const i8, ans as *mut i8) });
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(ans as *mut libc::c_void)
                    });
                }
            } else {
                xmlFreeURI(uri);
                ans = unsafe {
                    xmlCatalogResolveSystem(*argv.offset(i as isize) as *const xmlChar)
                };
                if ans.is_null() {
                    (unsafe {
                        printf(
                            b"No entry for SYSTEM %s\n\0" as *const u8 as *const i8,
                            *argv.offset(i as isize),
                        )
                    });
                    ans = unsafe {
                        xmlCatalogResolveURI(*argv.offset(i as isize) as *const xmlChar)
                    };
                    if ans.is_null() {
                        (unsafe {
                            printf(
                                b"No entry for URI %s\n\0" as *const u8 as *const i8,
                                *argv.offset(i as isize),
                            )
                        });
                        exit_value = 4 as i32;
                    } else {
                        (unsafe { printf(b"%s\n\0" as *const u8 as *const i8, ans as *mut i8) });
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(ans as *mut libc::c_void)
                        });
                    }
                } else {
                    (unsafe { printf(b"%s\n\0" as *const u8 as *const i8, ans as *mut i8) });
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(ans as *mut libc::c_void)
                    });
                }
            }
            i += 1;
        }
    }
    if (unsafe { sgml }) == 0
        && ((unsafe { add }) != 0
            || (unsafe { del }) != 0
            || (unsafe { create }) != 0
            || (unsafe { convert }) != 0)
    {
        if (unsafe { noout }) != 0
            && !(unsafe { filename }).is_null()
            && (unsafe { *filename }) as i32 != 0
        {
            let mut out_0: *mut crate::src::tree::_IO_FILE = 0 as *mut FILE;
            out_0 = unsafe { fopen(filename, b"w\0" as *const u8 as *const i8) };
            if out_0.is_null() {
                (unsafe {
                    fprintf(
                        stderr,
                        b"could not open %s for saving\n\0" as *const u8 as *const i8,
                        filename,
                    )
                });
                exit_value = 2 as i32;
                (unsafe { noout = 0 as i32 });
            } else {
                (unsafe { xmlCatalogDump(out_0) });
            }
        } else {
            (unsafe { xmlCatalogDump(stdout) });
        }
    }
    (unsafe { xmlCleanupParser() });
    xmlMemoryDump();
    return exit_value;
}
pub fn main() {
    let mut args: Vec<*mut i8> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
     {
        ::std::process::exit(
            main_0((args.len() - 1) as i32, args.as_mut_ptr() as *mut *mut i8) as i32,
        )
    }
}

