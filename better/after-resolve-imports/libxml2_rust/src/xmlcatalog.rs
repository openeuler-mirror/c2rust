use ::libc;
extern "C" {
    
    
    
    
    static mut stdin: *mut FILE;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn remove(__filename: *const i8) -> i32;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fflush(__stream: *mut FILE) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    
    fn fgets(
        __s: *mut i8,
        __n: i32,
        __stream: *mut FILE,
    ) -> *mut i8;
    fn memset(
        _: *mut libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn strlen(_: *const i8) -> u64;
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::catalog::xmlACatalogAdd;
pub use crate::src::catalog::xmlACatalogDump;
pub use crate::src::catalog::xmlACatalogRemove;
pub use crate::src::catalog::xmlCatalogAdd;
pub use crate::src::catalog::xmlCatalogConvert;
pub use crate::src::catalog::xmlCatalogDump;
pub use crate::src::catalog::xmlCatalogIsEmpty;
pub use crate::src::catalog::xmlCatalogRemove;
pub use crate::src::catalog::xmlCatalogResolve;
pub use crate::src::catalog::xmlCatalogResolvePublic;
pub use crate::src::catalog::xmlCatalogResolveSystem;
pub use crate::src::catalog::xmlCatalogResolveURI;
pub use crate::src::catalog::xmlCatalogSetDebug;
pub use crate::src::catalog::xmlInitializeCatalog;
pub use crate::src::catalog::xmlLoadCatalog;
pub use crate::src::catalog::xmlLoadSGMLSuperCatalog;
pub use crate::src::catalog::xmlNewCatalog;
pub use crate::src::parser::xmlCleanupParser;
pub use crate::src::parserInternals::xmlCheckVersion;
pub use crate::src::uri::xmlFreeURI;
pub use crate::src::uri::xmlParseURI;
pub use crate::src::xmlmemory::xmlMemoryDump;
pub use crate::src::catalog::_xmlCatalog;
pub use crate::src::HTMLtree::_IO_codecvt;
pub use crate::src::buf::_IO_marker;
pub use crate::src::globals::xmlFree;
pub use crate::src::python::types::_IO_wide_data;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
pub type size_t = crate::src::HTMLparser::size_t;
pub type __off_t = crate::src::HTMLtree::__off_t;
pub type __off64_t = crate::src::HTMLtree::__off64_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::HTMLtree::_IO_FILE;
pub type _IO_lock_t = crate::src::HTMLtree::_IO_lock_t;
pub type FILE = crate::src::HTMLtree::FILE;
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
// #[derive(Copy, Clone)]

pub type _xmlURI = crate::src::SAX2::_xmlURI;
pub type xmlURI = crate::src::SAX2::xmlURI;
pub type xmlURIPtr = crate::src::SAX2::xmlURIPtr;
pub type xmlCatalog = crate::src::catalog::xmlCatalog;
pub type xmlCatalogPtr = crate::src::catalog::xmlCatalogPtr;
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
unsafe extern "C" fn xmlShellReadline(
    mut prompt: *const i8,
) -> *mut i8 {
    let mut line_read: [i8; 501] = [0; 501];
    let mut ret: *mut i8 = 0 as *mut i8;
    let mut len: i32 = 0;
    if !prompt.is_null() {
        fprintf(stdout, b"%s\0" as *const u8 as *const i8, prompt);
    }
    fflush(stdout);
    if (fgets(line_read.as_mut_ptr(), 500 as i32, stdin)).is_null() {
        return 0 as *mut i8;
    }
    line_read[500 as i32 as usize] = 0 as i32 as i8;
    len = strlen(line_read.as_mut_ptr()) as i32;
    ret = malloc((len + 1 as i32) as u64) as *mut i8;
    if !ret.is_null() {
        memcpy(
            ret as *mut libc::c_void,
            line_read.as_mut_ptr() as *const libc::c_void,
            (len + 1 as i32) as u64,
        );
    }
    return ret;
}
unsafe extern "C" fn usershell() {
    let mut cmdline: *mut i8 = 0 as *mut i8;
    let mut cur: *mut i8 = 0 as *mut i8;
    let mut nbargs: i32 = 0;
    let mut command: [i8; 100] = [0; 100];
    let mut arg: [i8; 400] = [0; 400];
    let mut argv: [*mut i8; 20] = [0 as *mut i8; 20];
    let mut i: i32 = 0;
    let mut ret: i32 = 0;
    let mut ans: *mut xmlChar = 0 as *mut xmlChar;
    loop {
        cmdline = xmlShellReadline(b"> \0" as *const u8 as *const i8);
        if cmdline.is_null() {
            return;
        }
        cur = cmdline;
        nbargs = 0 as i32;
        while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32 {
            cur = cur.offset(1);
        }
        i = 0 as i32;
        while *cur as i32 != ' ' as i32 && *cur as i32 != '\t' as i32
            && *cur as i32 != '\n' as i32 && *cur as i32 != '\r' as i32
        {
            if *cur as i32 == 0 as i32 {
                break;
            }
            let fresh0 = cur;
            cur = cur.offset(1);
            let fresh1 = i;
            i = i + 1;
            command[fresh1 as usize] = *fresh0;
        }
        command[i as usize] = 0 as i32 as i8;
        if i == 0 as i32 {
            free(cmdline as *mut libc::c_void);
        } else {
            memset(
                arg.as_mut_ptr() as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<[i8; 400]>() as u64,
            );
            while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32
            {
                cur = cur.offset(1);
            }
            i = 0 as i32;
            while *cur as i32 != '\n' as i32
                && *cur as i32 != '\r' as i32
                && *cur as i32 != 0 as i32
            {
                if *cur as i32 == 0 as i32 {
                    break;
                }
                let fresh2 = cur;
                cur = cur.offset(1);
                let fresh3 = i;
                i = i + 1;
                arg[fresh3 as usize] = *fresh2;
            }
            arg[i as usize] = 0 as i32 as i8;
            i = 0 as i32;
            nbargs = 0 as i32;
            cur = arg.as_mut_ptr();
            memset(
                argv.as_mut_ptr() as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<[*mut i8; 20]>() as u64,
            );
            while *cur as i32 != 0 as i32 {
                while *cur as i32 == ' ' as i32
                    || *cur as i32 == '\t' as i32
                {
                    cur = cur.offset(1);
                }
                if *cur as i32 == '\'' as i32 {
                    cur = cur.offset(1);
                    argv[i as usize] = cur;
                    while *cur as i32 != 0 as i32
                        && *cur as i32 != '\'' as i32
                    {
                        cur = cur.offset(1);
                    }
                    if *cur as i32 == '\'' as i32 {
                        *cur = 0 as i32 as i8;
                        nbargs += 1;
                        i += 1;
                        cur = cur.offset(1);
                    }
                } else if *cur as i32 == '"' as i32 {
                    cur = cur.offset(1);
                    argv[i as usize] = cur;
                    while *cur as i32 != 0 as i32
                        && *cur as i32 != '"' as i32
                    {
                        cur = cur.offset(1);
                    }
                    if *cur as i32 == '"' as i32 {
                        *cur = 0 as i32 as i8;
                        nbargs += 1;
                        i += 1;
                        cur = cur.offset(1);
                    }
                } else {
                    argv[i as usize] = cur;
                    while *cur as i32 != 0 as i32
                        && *cur as i32 != ' ' as i32
                        && *cur as i32 != '\t' as i32
                    {
                        cur = cur.offset(1);
                    }
                    *cur = 0 as i32 as i8;
                    nbargs += 1;
                    i += 1;
                    cur = cur.offset(1);
                }
            }
            if strcmp(
                command.as_mut_ptr(),
                b"exit\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    command.as_mut_ptr(),
                    b"quit\0" as *const u8 as *const i8,
                ) == 0
                || strcmp(
                    command.as_mut_ptr(),
                    b"bye\0" as *const u8 as *const i8,
                ) == 0
            {
                free(cmdline as *mut libc::c_void);
                break;
            } else {
                if strcmp(
                    command.as_mut_ptr(),
                    b"public\0" as *const u8 as *const i8,
                ) == 0
                {
                    if nbargs != 1 as i32 {
                        printf(
                            b"public requires 1 arguments\n\0" as *const u8
                                as *const i8,
                        );
                    } else {
                        ans = xmlCatalogResolvePublic(
                            argv[0 as i32 as usize] as *const xmlChar,
                        );
                        if ans.is_null() {
                            printf(
                                b"No entry for PUBLIC %s\n\0" as *const u8
                                    as *const i8,
                                argv[0 as i32 as usize],
                            );
                        } else {
                            printf(
                                b"%s\n\0" as *const u8 as *const i8,
                                ans as *mut i8,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(ans as *mut libc::c_void);
                        }
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"system\0" as *const u8 as *const i8,
                    ) == 0
                    {
                    if nbargs != 1 as i32 {
                        printf(
                            b"system requires 1 arguments\n\0" as *const u8
                                as *const i8,
                        );
                    } else {
                        ans = xmlCatalogResolveSystem(
                            argv[0 as i32 as usize] as *const xmlChar,
                        );
                        if ans.is_null() {
                            printf(
                                b"No entry for SYSTEM %s\n\0" as *const u8
                                    as *const i8,
                                argv[0 as i32 as usize],
                            );
                        } else {
                            printf(
                                b"%s\n\0" as *const u8 as *const i8,
                                ans as *mut i8,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(ans as *mut libc::c_void);
                        }
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"add\0" as *const u8 as *const i8,
                    ) == 0
                    {
                    if nbargs != 3 as i32 && nbargs != 2 as i32 {
                        printf(
                            b"add requires 2 or 3 arguments\n\0" as *const u8
                                as *const i8,
                        );
                    } else {
                        if (argv[2 as i32 as usize]).is_null() {
                            ret = xmlCatalogAdd(
                                argv[0 as i32 as usize] as *mut xmlChar,
                                0 as *const xmlChar,
                                argv[1 as i32 as usize] as *mut xmlChar,
                            );
                        } else {
                            ret = xmlCatalogAdd(
                                argv[0 as i32 as usize] as *mut xmlChar,
                                argv[1 as i32 as usize] as *mut xmlChar,
                                argv[2 as i32 as usize] as *mut xmlChar,
                            );
                        }
                        if ret != 0 as i32 {
                            printf(
                                b"add command failed\n\0" as *const u8
                                    as *const i8,
                            );
                        }
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"del\0" as *const u8 as *const i8,
                    ) == 0
                    {
                    if nbargs != 1 as i32 {
                        printf(
                            b"del requires 1\n\0" as *const u8 as *const i8,
                        );
                    } else {
                        ret = xmlCatalogRemove(
                            argv[0 as i32 as usize] as *mut xmlChar,
                        );
                        if ret <= 0 as i32 {
                            printf(
                                b"del command failed\n\0" as *const u8
                                    as *const i8,
                            );
                        }
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"resolve\0" as *const u8 as *const i8,
                    ) == 0
                    {
                    if nbargs != 2 as i32 {
                        printf(
                            b"resolve requires 2 arguments\n\0" as *const u8
                                as *const i8,
                        );
                    } else {
                        ans = xmlCatalogResolve(
                            argv[0 as i32 as usize] as *mut xmlChar,
                            argv[1 as i32 as usize] as *mut xmlChar,
                        );
                        if ans.is_null() {
                            printf(
                                b"Resolver failed to find an answer\n\0" as *const u8
                                    as *const i8,
                            );
                        } else {
                            printf(
                                b"%s\n\0" as *const u8 as *const i8,
                                ans as *mut i8,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(ans as *mut libc::c_void);
                        }
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"dump\0" as *const u8 as *const i8,
                    ) == 0
                    {
                    if nbargs != 0 as i32 {
                        printf(
                            b"dump has no arguments\n\0" as *const u8
                                as *const i8,
                        );
                    } else {
                        xmlCatalogDump(stdout);
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"debug\0" as *const u8 as *const i8,
                    ) == 0
                    {
                    if nbargs != 0 as i32 {
                        printf(
                            b"debug has no arguments\n\0" as *const u8
                                as *const i8,
                        );
                    } else {
                        verbose += 1;
                        xmlCatalogSetDebug(verbose);
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"quiet\0" as *const u8 as *const i8,
                    ) == 0
                    {
                    if nbargs != 0 as i32 {
                        printf(
                            b"quiet has no arguments\n\0" as *const u8
                                as *const i8,
                        );
                    } else {
                        if verbose > 0 as i32 {
                            verbose -= 1;
                        }
                        xmlCatalogSetDebug(verbose);
                    }
                } else {
                    if strcmp(
                        command.as_mut_ptr(),
                        b"help\0" as *const u8 as *const i8,
                    ) != 0
                    {
                        printf(
                            b"Unrecognized command %s\n\0" as *const u8
                                as *const i8,
                            command.as_mut_ptr(),
                        );
                    }
                    printf(
                        b"Commands available:\n\0" as *const u8 as *const i8,
                    );
                    printf(
                        b"\tpublic PublicID: make a PUBLIC identifier lookup\n\0"
                            as *const u8 as *const i8,
                    );
                    printf(
                        b"\tsystem SystemID: make a SYSTEM identifier lookup\n\0"
                            as *const u8 as *const i8,
                    );
                    printf(
                        b"\tresolve PublicID SystemID: do a full resolver lookup\n\0"
                            as *const u8 as *const i8,
                    );
                    printf(
                        b"\tadd 'type' 'orig' 'replace' : add an entry\n\0" as *const u8
                            as *const i8,
                    );
                    printf(
                        b"\tdel 'values' : remove values\n\0" as *const u8
                            as *const i8,
                    );
                    printf(
                        b"\tdump: print the current catalog state\n\0" as *const u8
                            as *const i8,
                    );
                    printf(
                        b"\tdebug: increase the verbosity level\n\0" as *const u8
                            as *const i8,
                    );
                    printf(
                        b"\tquiet: decrease the verbosity level\n\0" as *const u8
                            as *const i8,
                    );
                    printf(
                        b"\texit:  quit the shell\n\0" as *const u8
                            as *const i8,
                    );
                }
                free(cmdline as *mut libc::c_void);
            }
        }
    };
}
unsafe extern "C" fn usage(mut name: *const i8) {
    printf(
        b"Usage : %s [options] catalogfile entities...\n\tParse the catalog file (void specification possibly expressed as \"\"\n\tappoints the default system one) and query it for the entities\n\t--sgml : handle SGML Super catalogs for --add and --del\n\t--shell : run a shell allowing interactive queries\n\t--create : create a new catalog\n\t--add 'type' 'orig' 'replace' : add an XML entry\n\t--add 'entry' : add an SGML entry\n\0"
            as *const u8 as *const i8,
        name,
    );
    printf(
        b"\t--del 'values' : remove values\n\t--noout: avoid dumping the result on stdout\n\t         used with --add or --del, it saves the catalog changes\n\t         and with --sgml it automatically updates the super catalog\n\t--no-super-update: do not update the SGML super catalog\n\t-v --verbose : provide debug information\n\0"
            as *const u8 as *const i8,
    );
}
unsafe fn main_0(
    mut argc: i32,
    mut argv: *mut *mut i8,
) -> i32 {
    let mut i: i32 = 0;
    let mut ret: i32 = 0;
    let mut exit_value: i32 = 0 as i32;
    if argc <= 1 as i32 {
        usage(*argv.offset(0 as i32 as isize));
        return 1 as i32;
    }
    xmlCheckVersion(21000 as i32);
    i = 1 as i32;
    while i < argc {
        if strcmp(*argv.offset(i as isize), b"-\0" as *const u8 as *const i8)
            == 0
        {
            break;
        }
        if *(*argv.offset(i as isize)).offset(0 as i32 as isize) as i32
            != '-' as i32
        {
            break;
        }
        if strcmp(
            *argv.offset(i as isize),
            b"-verbose\0" as *const u8 as *const i8,
        ) == 0
            || strcmp(
                *argv.offset(i as isize),
                b"-v\0" as *const u8 as *const i8,
            ) == 0
            || strcmp(
                *argv.offset(i as isize),
                b"--verbose\0" as *const u8 as *const i8,
            ) == 0
        {
            verbose += 1;
            xmlCatalogSetDebug(verbose);
        } else if strcmp(
                *argv.offset(i as isize),
                b"-noout\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--noout\0" as *const u8 as *const i8,
                ) == 0
            {
            noout = 1 as i32;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-shell\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--shell\0" as *const u8 as *const i8,
                ) == 0
            {
            shell += 1;
            noout = 1 as i32;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-sgml\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--sgml\0" as *const u8 as *const i8,
                ) == 0
            {
            sgml += 1;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-create\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--create\0" as *const u8 as *const i8,
                ) == 0
            {
            create += 1;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-convert\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--convert\0" as *const u8 as *const i8,
                ) == 0
            {
            convert += 1;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-no-super-update\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--no-super-update\0" as *const u8 as *const i8,
                ) == 0
            {
            no_super_update += 1;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-add\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--add\0" as *const u8 as *const i8,
                ) == 0
            {
            if sgml != 0 {
                i += 2 as i32;
            } else {
                i += 3 as i32;
            }
            add += 1;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-del\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--del\0" as *const u8 as *const i8,
                ) == 0
            {
            i += 1 as i32;
            del += 1;
        } else {
            fprintf(
                stderr,
                b"Unknown option %s\n\0" as *const u8 as *const i8,
                *argv.offset(i as isize),
            );
            usage(*argv.offset(0 as i32 as isize));
            return 1 as i32;
        }
        i += 1;
    }
    i = 1 as i32;
    while i < argc {
        if strcmp(
            *argv.offset(i as isize),
            b"-add\0" as *const u8 as *const i8,
        ) == 0
            || strcmp(
                *argv.offset(i as isize),
                b"--add\0" as *const u8 as *const i8,
            ) == 0
        {
            if sgml != 0 {
                i += 2 as i32;
            } else {
                i += 3 as i32;
            }
        } else if strcmp(
                *argv.offset(i as isize),
                b"-del\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--del\0" as *const u8 as *const i8,
                ) == 0
            {
            i += 1 as i32;
            if i == argc || sgml != 0 && i + 1 as i32 == argc {
                fprintf(
                    stderr,
                    b"No catalog entry specified to remove from\n\0" as *const u8
                        as *const i8,
                );
                usage(*argv.offset(0 as i32 as isize));
                return 1 as i32;
            }
        } else if !(*(*argv.offset(i as isize)).offset(0 as i32 as isize)
                as i32 == '-' as i32)
            {
            if filename.is_null()
                && *(*argv.offset(i as isize)).offset(0 as i32 as isize)
                    as i32 == '\u{0}' as i32
            {
                xmlInitializeCatalog();
            } else {
                filename = *argv.offset(i as isize);
                ret = xmlLoadCatalog(*argv.offset(i as isize));
                if ret < 0 as i32 && create != 0 {
                    xmlCatalogAdd(
                        b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                        *argv.offset(i as isize) as *mut xmlChar,
                        0 as *const xmlChar,
                    );
                }
            }
            break;
        }
        i += 1;
    }
    if convert != 0 {
        ret = xmlCatalogConvert();
    }
    if add != 0 || del != 0 {
        i = 1 as i32;
        while i < argc {
            if strcmp(
                *argv.offset(i as isize),
                b"-\0" as *const u8 as *const i8,
            ) == 0
            {
                break;
            }
            if !(*(*argv.offset(i as isize)).offset(0 as i32 as isize)
                as i32 != '-' as i32)
            {
                if !(strcmp(
                    *argv.offset(i as isize),
                    b"-add\0" as *const u8 as *const i8,
                ) != 0
                    && strcmp(
                        *argv.offset(i as isize),
                        b"--add\0" as *const u8 as *const i8,
                    ) != 0
                    && strcmp(
                        *argv.offset(i as isize),
                        b"-del\0" as *const u8 as *const i8,
                    ) != 0
                    && strcmp(
                        *argv.offset(i as isize),
                        b"--del\0" as *const u8 as *const i8,
                    ) != 0)
                {
                    if sgml != 0 {
                        let mut catal: xmlCatalogPtr = 0 as xmlCatalogPtr;
                        let mut super_0: xmlCatalogPtr = 0 as xmlCatalogPtr;
                        catal = xmlLoadSGMLSuperCatalog(
                            *argv.offset((i + 1 as i32) as isize),
                        );
                        if strcmp(
                            *argv.offset(i as isize),
                            b"-add\0" as *const u8 as *const i8,
                        ) == 0
                            || strcmp(
                                *argv.offset(i as isize),
                                b"--add\0" as *const u8 as *const i8,
                            ) == 0
                        {
                            if catal.is_null() {
                                catal = xmlNewCatalog(1 as i32);
                            }
                            xmlACatalogAdd(
                                catal,
                                b"CATALOG\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                *argv.offset((i + 2 as i32) as isize)
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            if no_super_update == 0 {
                                super_0 = xmlLoadSGMLSuperCatalog(
                                    b"/usr/local/etc/sgml/catalog\0" as *const u8
                                        as *const i8,
                                );
                                if super_0.is_null() {
                                    super_0 = xmlNewCatalog(1 as i32);
                                }
                                xmlACatalogAdd(
                                    super_0,
                                    b"CATALOG\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    *argv.offset((i + 1 as i32) as isize)
                                        as *mut xmlChar,
                                    0 as *const xmlChar,
                                );
                            }
                        } else {
                            if !catal.is_null() {
                                ret = xmlACatalogRemove(
                                    catal,
                                    *argv.offset((i + 2 as i32) as isize)
                                        as *mut xmlChar,
                                );
                            } else {
                                ret = -(1 as i32);
                            }
                            if ret < 0 as i32 {
                                fprintf(
                                    stderr,
                                    b"Failed to remove entry from %s\n\0" as *const u8
                                        as *const i8,
                                    *argv.offset((i + 1 as i32) as isize),
                                );
                                exit_value = 1 as i32;
                            }
                            if no_super_update == 0 && noout != 0 && !catal.is_null()
                                && xmlCatalogIsEmpty(catal) != 0
                            {
                                super_0 = xmlLoadSGMLSuperCatalog(
                                    b"/usr/local/etc/sgml/catalog\0" as *const u8
                                        as *const i8,
                                );
                                if !super_0.is_null() {
                                    ret = xmlACatalogRemove(
                                        super_0,
                                        *argv.offset((i + 1 as i32) as isize)
                                            as *mut xmlChar,
                                    );
                                    if ret < 0 as i32 {
                                        fprintf(
                                            stderr,
                                            b"Failed to remove entry from %s\n\0" as *const u8
                                                as *const i8,
                                            b"/usr/local/etc/sgml/catalog\0" as *const u8
                                                as *const i8,
                                        );
                                        exit_value = 1 as i32;
                                    }
                                }
                            }
                        }
                        if noout != 0 {
                            let mut out: *mut FILE = 0 as *mut FILE;
                            if xmlCatalogIsEmpty(catal) != 0 {
                                remove(*argv.offset((i + 1 as i32) as isize));
                            } else {
                                out = fopen(
                                    *argv.offset((i + 1 as i32) as isize),
                                    b"w\0" as *const u8 as *const i8,
                                );
                                if out.is_null() {
                                    fprintf(
                                        stderr,
                                        b"could not open %s for saving\n\0" as *const u8
                                            as *const i8,
                                        *argv.offset((i + 1 as i32) as isize),
                                    );
                                    exit_value = 2 as i32;
                                    noout = 0 as i32;
                                } else {
                                    xmlACatalogDump(catal, out);
                                    fclose(out);
                                }
                            }
                            if no_super_update == 0 && !super_0.is_null() {
                                if xmlCatalogIsEmpty(super_0) != 0 {
                                    remove(
                                        b"/usr/local/etc/sgml/catalog\0" as *const u8
                                            as *const i8,
                                    );
                                } else {
                                    out = fopen(
                                        b"/usr/local/etc/sgml/catalog\0" as *const u8
                                            as *const i8,
                                        b"w\0" as *const u8 as *const i8,
                                    );
                                    if out.is_null() {
                                        fprintf(
                                            stderr,
                                            b"could not open %s for saving\n\0" as *const u8
                                                as *const i8,
                                            b"/usr/local/etc/sgml/catalog\0" as *const u8
                                                as *const i8,
                                        );
                                        exit_value = 2 as i32;
                                        noout = 0 as i32;
                                    } else {
                                        xmlACatalogDump(super_0, out);
                                        fclose(out);
                                    }
                                }
                            }
                        } else {
                            xmlACatalogDump(catal, stdout);
                        }
                        i += 2 as i32;
                    } else if strcmp(
                            *argv.offset(i as isize),
                            b"-add\0" as *const u8 as *const i8,
                        ) == 0
                            || strcmp(
                                *argv.offset(i as isize),
                                b"--add\0" as *const u8 as *const i8,
                            ) == 0
                        {
                        if (*argv.offset((i + 3 as i32) as isize)).is_null()
                            || *(*argv.offset((i + 3 as i32) as isize))
                                .offset(0 as i32 as isize) as i32
                                == 0 as i32
                        {
                            ret = xmlCatalogAdd(
                                *argv.offset((i + 1 as i32) as isize)
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                                *argv.offset((i + 2 as i32) as isize)
                                    as *mut xmlChar,
                            );
                        } else {
                            ret = xmlCatalogAdd(
                                *argv.offset((i + 1 as i32) as isize)
                                    as *mut xmlChar,
                                *argv.offset((i + 2 as i32) as isize)
                                    as *mut xmlChar,
                                *argv.offset((i + 3 as i32) as isize)
                                    as *mut xmlChar,
                            );
                        }
                        if ret != 0 as i32 {
                            printf(
                                b"add command failed\n\0" as *const u8
                                    as *const i8,
                            );
                            exit_value = 3 as i32;
                        }
                        i += 3 as i32;
                    } else if strcmp(
                            *argv.offset(i as isize),
                            b"-del\0" as *const u8 as *const i8,
                        ) == 0
                            || strcmp(
                                *argv.offset(i as isize),
                                b"--del\0" as *const u8 as *const i8,
                            ) == 0
                        {
                        ret = xmlCatalogRemove(
                            *argv.offset((i + 1 as i32) as isize) as *mut xmlChar,
                        );
                        if ret < 0 as i32 {
                            fprintf(
                                stderr,
                                b"Failed to remove entry %s\n\0" as *const u8
                                    as *const i8,
                                *argv.offset((i + 1 as i32) as isize),
                            );
                            exit_value = 1 as i32;
                        }
                        i += 1 as i32;
                    }
                }
            }
            i += 1;
        }
    } else if shell != 0 {
        usershell();
    } else {
        i += 1;
        while i < argc {
            let mut uri: xmlURIPtr = 0 as *mut xmlURI;
            let mut ans: *mut xmlChar = 0 as *mut xmlChar;
            uri = xmlParseURI(*argv.offset(i as isize));
            if uri.is_null() {
                ans = xmlCatalogResolvePublic(
                    *argv.offset(i as isize) as *const xmlChar,
                );
                if ans.is_null() {
                    printf(
                        b"No entry for PUBLIC %s\n\0" as *const u8
                            as *const i8,
                        *argv.offset(i as isize),
                    );
                    exit_value = 4 as i32;
                } else {
                    printf(
                        b"%s\n\0" as *const u8 as *const i8,
                        ans as *mut i8,
                    );
                    xmlFree
                        .expect("non-null function pointer")(ans as *mut libc::c_void);
                }
            } else {
                xmlFreeURI(uri);
                ans = xmlCatalogResolveSystem(
                    *argv.offset(i as isize) as *const xmlChar,
                );
                if ans.is_null() {
                    printf(
                        b"No entry for SYSTEM %s\n\0" as *const u8
                            as *const i8,
                        *argv.offset(i as isize),
                    );
                    ans = xmlCatalogResolveURI(
                        *argv.offset(i as isize) as *const xmlChar,
                    );
                    if ans.is_null() {
                        printf(
                            b"No entry for URI %s\n\0" as *const u8
                                as *const i8,
                            *argv.offset(i as isize),
                        );
                        exit_value = 4 as i32;
                    } else {
                        printf(
                            b"%s\n\0" as *const u8 as *const i8,
                            ans as *mut i8,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(ans as *mut libc::c_void);
                    }
                } else {
                    printf(
                        b"%s\n\0" as *const u8 as *const i8,
                        ans as *mut i8,
                    );
                    xmlFree
                        .expect("non-null function pointer")(ans as *mut libc::c_void);
                }
            }
            i += 1;
        }
    }
    if sgml == 0 && (add != 0 || del != 0 || create != 0 || convert != 0) {
        if noout != 0 && !filename.is_null() && *filename as i32 != 0 {
            let mut out_0: *mut FILE = 0 as *mut FILE;
            out_0 = fopen(filename, b"w\0" as *const u8 as *const i8);
            if out_0.is_null() {
                fprintf(
                    stderr,
                    b"could not open %s for saving\n\0" as *const u8
                        as *const i8,
                    filename,
                );
                exit_value = 2 as i32;
                noout = 0 as i32;
            } else {
                xmlCatalogDump(out_0);
            }
        } else {
            xmlCatalogDump(stdout);
        }
    }
    xmlCleanupParser();
    xmlMemoryDump();
    return exit_value;
}
pub fn main() {
    let mut args: Vec::<*mut i8> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as i32,
                args.as_mut_ptr() as *mut *mut i8,
            ) as i32,
        )
    }
}
