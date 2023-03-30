use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    
    static mut stdin: *mut FILE;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn remove(__filename: *const libc::c_char) -> libc::c_int;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut FILE,
    ) -> *mut libc::c_char;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    
    
    static mut xmlFree: xmlFreeFunc;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
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
pub use crate::src::HTMLparser::xmlChar;
pub use crate::src::HTMLparser::size_t;
pub use crate::src::HTMLtree::__off_t;
pub use crate::src::HTMLtree::__off64_t;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLtree::_IO_FILE;
pub use crate::src::HTMLtree::_IO_lock_t;
pub use crate::src::HTMLtree::FILE;
pub use crate::src::HTMLparser::xmlFreeFunc;
// #[derive(Copy, Clone)]

pub use crate::src::SAX2::_xmlURI;
pub use crate::src::SAX2::xmlURI;
pub use crate::src::SAX2::xmlURIPtr;
pub use crate::src::catalog::xmlCatalog;
pub use crate::src::catalog::xmlCatalogPtr;
static mut shell: libc::c_int = 0 as libc::c_int;
static mut sgml: libc::c_int = 0 as libc::c_int;
static mut noout: libc::c_int = 0 as libc::c_int;
static mut create: libc::c_int = 0 as libc::c_int;
static mut add: libc::c_int = 0 as libc::c_int;
static mut del: libc::c_int = 0 as libc::c_int;
static mut convert: libc::c_int = 0 as libc::c_int;
static mut no_super_update: libc::c_int = 0 as libc::c_int;
static mut verbose: libc::c_int = 0 as libc::c_int;
static mut filename: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
unsafe extern "C" fn xmlShellReadline(
    mut prompt: *const libc::c_char,
) -> *mut libc::c_char {
    let mut line_read: [libc::c_char; 501] = [0; 501];
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: libc::c_int = 0;
    if !prompt.is_null() {
        fprintf(stdout, b"%s\0" as *const u8 as *const libc::c_char, prompt);
    }
    fflush(stdout);
    if (fgets(line_read.as_mut_ptr(), 500 as libc::c_int, stdin)).is_null() {
        return 0 as *mut libc::c_char;
    }
    line_read[500 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
    len = strlen(line_read.as_mut_ptr()) as libc::c_int;
    ret = malloc((len + 1 as libc::c_int) as libc::c_ulong) as *mut libc::c_char;
    if !ret.is_null() {
        memcpy(
            ret as *mut libc::c_void,
            line_read.as_mut_ptr() as *const libc::c_void,
            (len + 1 as libc::c_int) as libc::c_ulong,
        );
    }
    return ret;
}
unsafe extern "C" fn usershell() {
    let mut cmdline: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cur: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut nbargs: libc::c_int = 0;
    let mut command: [libc::c_char; 100] = [0; 100];
    let mut arg: [libc::c_char; 400] = [0; 400];
    let mut argv: [*mut libc::c_char; 20] = [0 as *mut libc::c_char; 20];
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut ans: *mut xmlChar = 0 as *mut xmlChar;
    loop {
        cmdline = xmlShellReadline(b"> \0" as *const u8 as *const libc::c_char);
        if cmdline.is_null() {
            return;
        }
        cur = cmdline;
        nbargs = 0 as libc::c_int;
        while *cur as libc::c_int == ' ' as i32 || *cur as libc::c_int == '\t' as i32 {
            cur = cur.offset(1);
        }
        i = 0 as libc::c_int;
        while *cur as libc::c_int != ' ' as i32 && *cur as libc::c_int != '\t' as i32
            && *cur as libc::c_int != '\n' as i32 && *cur as libc::c_int != '\r' as i32
        {
            if *cur as libc::c_int == 0 as libc::c_int {
                break;
            }
            let fresh0 = cur;
            cur = cur.offset(1);
            let fresh1 = i;
            i = i + 1;
            command[fresh1 as usize] = *fresh0;
        }
        command[i as usize] = 0 as libc::c_int as libc::c_char;
        if i == 0 as libc::c_int {
            free(cmdline as *mut libc::c_void);
        } else {
            memset(
                arg.as_mut_ptr() as *mut libc::c_void,
                0 as libc::c_int,
                ::std::mem::size_of::<[libc::c_char; 400]>() as libc::c_ulong,
            );
            while *cur as libc::c_int == ' ' as i32 || *cur as libc::c_int == '\t' as i32
            {
                cur = cur.offset(1);
            }
            i = 0 as libc::c_int;
            while *cur as libc::c_int != '\n' as i32
                && *cur as libc::c_int != '\r' as i32
                && *cur as libc::c_int != 0 as libc::c_int
            {
                if *cur as libc::c_int == 0 as libc::c_int {
                    break;
                }
                let fresh2 = cur;
                cur = cur.offset(1);
                let fresh3 = i;
                i = i + 1;
                arg[fresh3 as usize] = *fresh2;
            }
            arg[i as usize] = 0 as libc::c_int as libc::c_char;
            i = 0 as libc::c_int;
            nbargs = 0 as libc::c_int;
            cur = arg.as_mut_ptr();
            memset(
                argv.as_mut_ptr() as *mut libc::c_void,
                0 as libc::c_int,
                ::std::mem::size_of::<[*mut libc::c_char; 20]>() as libc::c_ulong,
            );
            while *cur as libc::c_int != 0 as libc::c_int {
                while *cur as libc::c_int == ' ' as i32
                    || *cur as libc::c_int == '\t' as i32
                {
                    cur = cur.offset(1);
                }
                if *cur as libc::c_int == '\'' as i32 {
                    cur = cur.offset(1);
                    argv[i as usize] = cur;
                    while *cur as libc::c_int != 0 as libc::c_int
                        && *cur as libc::c_int != '\'' as i32
                    {
                        cur = cur.offset(1);
                    }
                    if *cur as libc::c_int == '\'' as i32 {
                        *cur = 0 as libc::c_int as libc::c_char;
                        nbargs += 1;
                        i += 1;
                        cur = cur.offset(1);
                    }
                } else if *cur as libc::c_int == '"' as i32 {
                    cur = cur.offset(1);
                    argv[i as usize] = cur;
                    while *cur as libc::c_int != 0 as libc::c_int
                        && *cur as libc::c_int != '"' as i32
                    {
                        cur = cur.offset(1);
                    }
                    if *cur as libc::c_int == '"' as i32 {
                        *cur = 0 as libc::c_int as libc::c_char;
                        nbargs += 1;
                        i += 1;
                        cur = cur.offset(1);
                    }
                } else {
                    argv[i as usize] = cur;
                    while *cur as libc::c_int != 0 as libc::c_int
                        && *cur as libc::c_int != ' ' as i32
                        && *cur as libc::c_int != '\t' as i32
                    {
                        cur = cur.offset(1);
                    }
                    *cur = 0 as libc::c_int as libc::c_char;
                    nbargs += 1;
                    i += 1;
                    cur = cur.offset(1);
                }
            }
            if strcmp(
                command.as_mut_ptr(),
                b"exit\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    command.as_mut_ptr(),
                    b"quit\0" as *const u8 as *const libc::c_char,
                ) == 0
                || strcmp(
                    command.as_mut_ptr(),
                    b"bye\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
                free(cmdline as *mut libc::c_void);
                break;
            } else {
                if strcmp(
                    command.as_mut_ptr(),
                    b"public\0" as *const u8 as *const libc::c_char,
                ) == 0
                {
                    if nbargs != 1 as libc::c_int {
                        printf(
                            b"public requires 1 arguments\n\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else {
                        ans = xmlCatalogResolvePublic(
                            argv[0 as libc::c_int as usize] as *const xmlChar,
                        );
                        if ans.is_null() {
                            printf(
                                b"No entry for PUBLIC %s\n\0" as *const u8
                                    as *const libc::c_char,
                                argv[0 as libc::c_int as usize],
                            );
                        } else {
                            printf(
                                b"%s\n\0" as *const u8 as *const libc::c_char,
                                ans as *mut libc::c_char,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(ans as *mut libc::c_void);
                        }
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"system\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    {
                    if nbargs != 1 as libc::c_int {
                        printf(
                            b"system requires 1 arguments\n\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else {
                        ans = xmlCatalogResolveSystem(
                            argv[0 as libc::c_int as usize] as *const xmlChar,
                        );
                        if ans.is_null() {
                            printf(
                                b"No entry for SYSTEM %s\n\0" as *const u8
                                    as *const libc::c_char,
                                argv[0 as libc::c_int as usize],
                            );
                        } else {
                            printf(
                                b"%s\n\0" as *const u8 as *const libc::c_char,
                                ans as *mut libc::c_char,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(ans as *mut libc::c_void);
                        }
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"add\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    {
                    if nbargs != 3 as libc::c_int && nbargs != 2 as libc::c_int {
                        printf(
                            b"add requires 2 or 3 arguments\n\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else {
                        if (argv[2 as libc::c_int as usize]).is_null() {
                            ret = xmlCatalogAdd(
                                argv[0 as libc::c_int as usize] as *mut xmlChar,
                                0 as *const xmlChar,
                                argv[1 as libc::c_int as usize] as *mut xmlChar,
                            );
                        } else {
                            ret = xmlCatalogAdd(
                                argv[0 as libc::c_int as usize] as *mut xmlChar,
                                argv[1 as libc::c_int as usize] as *mut xmlChar,
                                argv[2 as libc::c_int as usize] as *mut xmlChar,
                            );
                        }
                        if ret != 0 as libc::c_int {
                            printf(
                                b"add command failed\n\0" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"del\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    {
                    if nbargs != 1 as libc::c_int {
                        printf(
                            b"del requires 1\n\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        ret = xmlCatalogRemove(
                            argv[0 as libc::c_int as usize] as *mut xmlChar,
                        );
                        if ret <= 0 as libc::c_int {
                            printf(
                                b"del command failed\n\0" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"resolve\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    {
                    if nbargs != 2 as libc::c_int {
                        printf(
                            b"resolve requires 2 arguments\n\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else {
                        ans = xmlCatalogResolve(
                            argv[0 as libc::c_int as usize] as *mut xmlChar,
                            argv[1 as libc::c_int as usize] as *mut xmlChar,
                        );
                        if ans.is_null() {
                            printf(
                                b"Resolver failed to find an answer\n\0" as *const u8
                                    as *const libc::c_char,
                            );
                        } else {
                            printf(
                                b"%s\n\0" as *const u8 as *const libc::c_char,
                                ans as *mut libc::c_char,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(ans as *mut libc::c_void);
                        }
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"dump\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    {
                    if nbargs != 0 as libc::c_int {
                        printf(
                            b"dump has no arguments\n\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else {
                        xmlCatalogDump(stdout);
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"debug\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    {
                    if nbargs != 0 as libc::c_int {
                        printf(
                            b"debug has no arguments\n\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else {
                        verbose += 1;
                        xmlCatalogSetDebug(verbose);
                    }
                } else if strcmp(
                        command.as_mut_ptr(),
                        b"quiet\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    {
                    if nbargs != 0 as libc::c_int {
                        printf(
                            b"quiet has no arguments\n\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else {
                        if verbose > 0 as libc::c_int {
                            verbose -= 1;
                        }
                        xmlCatalogSetDebug(verbose);
                    }
                } else {
                    if strcmp(
                        command.as_mut_ptr(),
                        b"help\0" as *const u8 as *const libc::c_char,
                    ) != 0
                    {
                        printf(
                            b"Unrecognized command %s\n\0" as *const u8
                                as *const libc::c_char,
                            command.as_mut_ptr(),
                        );
                    }
                    printf(
                        b"Commands available:\n\0" as *const u8 as *const libc::c_char,
                    );
                    printf(
                        b"\tpublic PublicID: make a PUBLIC identifier lookup\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    printf(
                        b"\tsystem SystemID: make a SYSTEM identifier lookup\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    printf(
                        b"\tresolve PublicID SystemID: do a full resolver lookup\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    printf(
                        b"\tadd 'type' 'orig' 'replace' : add an entry\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    printf(
                        b"\tdel 'values' : remove values\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    printf(
                        b"\tdump: print the current catalog state\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    printf(
                        b"\tdebug: increase the verbosity level\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    printf(
                        b"\tquiet: decrease the verbosity level\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    printf(
                        b"\texit:  quit the shell\n\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                free(cmdline as *mut libc::c_void);
            }
        }
    };
}
unsafe extern "C" fn usage(mut name: *const libc::c_char) {
    printf(
        b"Usage : %s [options] catalogfile entities...\n\tParse the catalog file (void specification possibly expressed as \"\"\n\tappoints the default system one) and query it for the entities\n\t--sgml : handle SGML Super catalogs for --add and --del\n\t--shell : run a shell allowing interactive queries\n\t--create : create a new catalog\n\t--add 'type' 'orig' 'replace' : add an XML entry\n\t--add 'entry' : add an SGML entry\n\0"
            as *const u8 as *const libc::c_char,
        name,
    );
    printf(
        b"\t--del 'values' : remove values\n\t--noout: avoid dumping the result on stdout\n\t         used with --add or --del, it saves the catalog changes\n\t         and with --sgml it automatically updates the super catalog\n\t--no-super-update: do not update the SGML super catalog\n\t-v --verbose : provide debug information\n\0"
            as *const u8 as *const libc::c_char,
    );
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut exit_value: libc::c_int = 0 as libc::c_int;
    if argc <= 1 as libc::c_int {
        usage(*argv.offset(0 as libc::c_int as isize));
        return 1 as libc::c_int;
    }
    xmlCheckVersion(21000 as libc::c_int);
    i = 1 as libc::c_int;
    while i < argc {
        if strcmp(*argv.offset(i as isize), b"-\0" as *const u8 as *const libc::c_char)
            == 0
        {
            break;
        }
        if *(*argv.offset(i as isize)).offset(0 as libc::c_int as isize) as libc::c_int
            != '-' as i32
        {
            break;
        }
        if strcmp(
            *argv.offset(i as isize),
            b"-verbose\0" as *const u8 as *const libc::c_char,
        ) == 0
            || strcmp(
                *argv.offset(i as isize),
                b"-v\0" as *const u8 as *const libc::c_char,
            ) == 0
            || strcmp(
                *argv.offset(i as isize),
                b"--verbose\0" as *const u8 as *const libc::c_char,
            ) == 0
        {
            verbose += 1;
            xmlCatalogSetDebug(verbose);
        } else if strcmp(
                *argv.offset(i as isize),
                b"-noout\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--noout\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
            noout = 1 as libc::c_int;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-shell\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--shell\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
            shell += 1;
            noout = 1 as libc::c_int;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-sgml\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--sgml\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
            sgml += 1;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-create\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--create\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
            create += 1;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-convert\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--convert\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
            convert += 1;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-no-super-update\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--no-super-update\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
            no_super_update += 1;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-add\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--add\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
            if sgml != 0 {
                i += 2 as libc::c_int;
            } else {
                i += 3 as libc::c_int;
            }
            add += 1;
        } else if strcmp(
                *argv.offset(i as isize),
                b"-del\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--del\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
            i += 1 as libc::c_int;
            del += 1;
        } else {
            fprintf(
                stderr,
                b"Unknown option %s\n\0" as *const u8 as *const libc::c_char,
                *argv.offset(i as isize),
            );
            usage(*argv.offset(0 as libc::c_int as isize));
            return 1 as libc::c_int;
        }
        i += 1;
    }
    i = 1 as libc::c_int;
    while i < argc {
        if strcmp(
            *argv.offset(i as isize),
            b"-add\0" as *const u8 as *const libc::c_char,
        ) == 0
            || strcmp(
                *argv.offset(i as isize),
                b"--add\0" as *const u8 as *const libc::c_char,
            ) == 0
        {
            if sgml != 0 {
                i += 2 as libc::c_int;
            } else {
                i += 3 as libc::c_int;
            }
        } else if strcmp(
                *argv.offset(i as isize),
                b"-del\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--del\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
            i += 1 as libc::c_int;
            if i == argc || sgml != 0 && i + 1 as libc::c_int == argc {
                fprintf(
                    stderr,
                    b"No catalog entry specified to remove from\n\0" as *const u8
                        as *const libc::c_char,
                );
                usage(*argv.offset(0 as libc::c_int as isize));
                return 1 as libc::c_int;
            }
        } else if !(*(*argv.offset(i as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int == '-' as i32)
            {
            if filename.is_null()
                && *(*argv.offset(i as isize)).offset(0 as libc::c_int as isize)
                    as libc::c_int == '\u{0}' as i32
            {
                xmlInitializeCatalog();
            } else {
                filename = *argv.offset(i as isize);
                ret = xmlLoadCatalog(*argv.offset(i as isize));
                if ret < 0 as libc::c_int && create != 0 {
                    xmlCatalogAdd(
                        b"catalog\0" as *const u8 as *const libc::c_char as *mut xmlChar,
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
        i = 1 as libc::c_int;
        while i < argc {
            if strcmp(
                *argv.offset(i as isize),
                b"-\0" as *const u8 as *const libc::c_char,
            ) == 0
            {
                break;
            }
            if !(*(*argv.offset(i as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int != '-' as i32)
            {
                if !(strcmp(
                    *argv.offset(i as isize),
                    b"-add\0" as *const u8 as *const libc::c_char,
                ) != 0
                    && strcmp(
                        *argv.offset(i as isize),
                        b"--add\0" as *const u8 as *const libc::c_char,
                    ) != 0
                    && strcmp(
                        *argv.offset(i as isize),
                        b"-del\0" as *const u8 as *const libc::c_char,
                    ) != 0
                    && strcmp(
                        *argv.offset(i as isize),
                        b"--del\0" as *const u8 as *const libc::c_char,
                    ) != 0)
                {
                    if sgml != 0 {
                        let mut catal: xmlCatalogPtr = 0 as xmlCatalogPtr;
                        let mut super_0: xmlCatalogPtr = 0 as xmlCatalogPtr;
                        catal = xmlLoadSGMLSuperCatalog(
                            *argv.offset((i + 1 as libc::c_int) as isize),
                        );
                        if strcmp(
                            *argv.offset(i as isize),
                            b"-add\0" as *const u8 as *const libc::c_char,
                        ) == 0
                            || strcmp(
                                *argv.offset(i as isize),
                                b"--add\0" as *const u8 as *const libc::c_char,
                            ) == 0
                        {
                            if catal.is_null() {
                                catal = xmlNewCatalog(1 as libc::c_int);
                            }
                            xmlACatalogAdd(
                                catal,
                                b"CATALOG\0" as *const u8 as *const libc::c_char
                                    as *mut xmlChar,
                                *argv.offset((i + 2 as libc::c_int) as isize)
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            if no_super_update == 0 {
                                super_0 = xmlLoadSGMLSuperCatalog(
                                    b"/usr/local/etc/sgml/catalog\0" as *const u8
                                        as *const libc::c_char,
                                );
                                if super_0.is_null() {
                                    super_0 = xmlNewCatalog(1 as libc::c_int);
                                }
                                xmlACatalogAdd(
                                    super_0,
                                    b"CATALOG\0" as *const u8 as *const libc::c_char
                                        as *mut xmlChar,
                                    *argv.offset((i + 1 as libc::c_int) as isize)
                                        as *mut xmlChar,
                                    0 as *const xmlChar,
                                );
                            }
                        } else {
                            if !catal.is_null() {
                                ret = xmlACatalogRemove(
                                    catal,
                                    *argv.offset((i + 2 as libc::c_int) as isize)
                                        as *mut xmlChar,
                                );
                            } else {
                                ret = -(1 as libc::c_int);
                            }
                            if ret < 0 as libc::c_int {
                                fprintf(
                                    stderr,
                                    b"Failed to remove entry from %s\n\0" as *const u8
                                        as *const libc::c_char,
                                    *argv.offset((i + 1 as libc::c_int) as isize),
                                );
                                exit_value = 1 as libc::c_int;
                            }
                            if no_super_update == 0 && noout != 0 && !catal.is_null()
                                && xmlCatalogIsEmpty(catal) != 0
                            {
                                super_0 = xmlLoadSGMLSuperCatalog(
                                    b"/usr/local/etc/sgml/catalog\0" as *const u8
                                        as *const libc::c_char,
                                );
                                if !super_0.is_null() {
                                    ret = xmlACatalogRemove(
                                        super_0,
                                        *argv.offset((i + 1 as libc::c_int) as isize)
                                            as *mut xmlChar,
                                    );
                                    if ret < 0 as libc::c_int {
                                        fprintf(
                                            stderr,
                                            b"Failed to remove entry from %s\n\0" as *const u8
                                                as *const libc::c_char,
                                            b"/usr/local/etc/sgml/catalog\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        exit_value = 1 as libc::c_int;
                                    }
                                }
                            }
                        }
                        if noout != 0 {
                            let mut out: *mut FILE = 0 as *mut FILE;
                            if xmlCatalogIsEmpty(catal) != 0 {
                                remove(*argv.offset((i + 1 as libc::c_int) as isize));
                            } else {
                                out = fopen(
                                    *argv.offset((i + 1 as libc::c_int) as isize),
                                    b"w\0" as *const u8 as *const libc::c_char,
                                );
                                if out.is_null() {
                                    fprintf(
                                        stderr,
                                        b"could not open %s for saving\n\0" as *const u8
                                            as *const libc::c_char,
                                        *argv.offset((i + 1 as libc::c_int) as isize),
                                    );
                                    exit_value = 2 as libc::c_int;
                                    noout = 0 as libc::c_int;
                                } else {
                                    xmlACatalogDump(catal, out);
                                    fclose(out);
                                }
                            }
                            if no_super_update == 0 && !super_0.is_null() {
                                if xmlCatalogIsEmpty(super_0) != 0 {
                                    remove(
                                        b"/usr/local/etc/sgml/catalog\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                } else {
                                    out = fopen(
                                        b"/usr/local/etc/sgml/catalog\0" as *const u8
                                            as *const libc::c_char,
                                        b"w\0" as *const u8 as *const libc::c_char,
                                    );
                                    if out.is_null() {
                                        fprintf(
                                            stderr,
                                            b"could not open %s for saving\n\0" as *const u8
                                                as *const libc::c_char,
                                            b"/usr/local/etc/sgml/catalog\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        exit_value = 2 as libc::c_int;
                                        noout = 0 as libc::c_int;
                                    } else {
                                        xmlACatalogDump(super_0, out);
                                        fclose(out);
                                    }
                                }
                            }
                        } else {
                            xmlACatalogDump(catal, stdout);
                        }
                        i += 2 as libc::c_int;
                    } else if strcmp(
                            *argv.offset(i as isize),
                            b"-add\0" as *const u8 as *const libc::c_char,
                        ) == 0
                            || strcmp(
                                *argv.offset(i as isize),
                                b"--add\0" as *const u8 as *const libc::c_char,
                            ) == 0
                        {
                        if (*argv.offset((i + 3 as libc::c_int) as isize)).is_null()
                            || *(*argv.offset((i + 3 as libc::c_int) as isize))
                                .offset(0 as libc::c_int as isize) as libc::c_int
                                == 0 as libc::c_int
                        {
                            ret = xmlCatalogAdd(
                                *argv.offset((i + 1 as libc::c_int) as isize)
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                                *argv.offset((i + 2 as libc::c_int) as isize)
                                    as *mut xmlChar,
                            );
                        } else {
                            ret = xmlCatalogAdd(
                                *argv.offset((i + 1 as libc::c_int) as isize)
                                    as *mut xmlChar,
                                *argv.offset((i + 2 as libc::c_int) as isize)
                                    as *mut xmlChar,
                                *argv.offset((i + 3 as libc::c_int) as isize)
                                    as *mut xmlChar,
                            );
                        }
                        if ret != 0 as libc::c_int {
                            printf(
                                b"add command failed\n\0" as *const u8
                                    as *const libc::c_char,
                            );
                            exit_value = 3 as libc::c_int;
                        }
                        i += 3 as libc::c_int;
                    } else if strcmp(
                            *argv.offset(i as isize),
                            b"-del\0" as *const u8 as *const libc::c_char,
                        ) == 0
                            || strcmp(
                                *argv.offset(i as isize),
                                b"--del\0" as *const u8 as *const libc::c_char,
                            ) == 0
                        {
                        ret = xmlCatalogRemove(
                            *argv.offset((i + 1 as libc::c_int) as isize) as *mut xmlChar,
                        );
                        if ret < 0 as libc::c_int {
                            fprintf(
                                stderr,
                                b"Failed to remove entry %s\n\0" as *const u8
                                    as *const libc::c_char,
                                *argv.offset((i + 1 as libc::c_int) as isize),
                            );
                            exit_value = 1 as libc::c_int;
                        }
                        i += 1 as libc::c_int;
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
                            as *const libc::c_char,
                        *argv.offset(i as isize),
                    );
                    exit_value = 4 as libc::c_int;
                } else {
                    printf(
                        b"%s\n\0" as *const u8 as *const libc::c_char,
                        ans as *mut libc::c_char,
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
                            as *const libc::c_char,
                        *argv.offset(i as isize),
                    );
                    ans = xmlCatalogResolveURI(
                        *argv.offset(i as isize) as *const xmlChar,
                    );
                    if ans.is_null() {
                        printf(
                            b"No entry for URI %s\n\0" as *const u8
                                as *const libc::c_char,
                            *argv.offset(i as isize),
                        );
                        exit_value = 4 as libc::c_int;
                    } else {
                        printf(
                            b"%s\n\0" as *const u8 as *const libc::c_char,
                            ans as *mut libc::c_char,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(ans as *mut libc::c_void);
                    }
                } else {
                    printf(
                        b"%s\n\0" as *const u8 as *const libc::c_char,
                        ans as *mut libc::c_char,
                    );
                    xmlFree
                        .expect("non-null function pointer")(ans as *mut libc::c_void);
                }
            }
            i += 1;
        }
    }
    if sgml == 0 && (add != 0 || del != 0 || create != 0 || convert != 0) {
        if noout != 0 && !filename.is_null() && *filename as libc::c_int != 0 {
            let mut out_0: *mut FILE = 0 as *mut FILE;
            out_0 = fopen(filename, b"w\0" as *const u8 as *const libc::c_char);
            if out_0.is_null() {
                fprintf(
                    stderr,
                    b"could not open %s for saving\n\0" as *const u8
                        as *const libc::c_char,
                    filename,
                );
                exit_value = 2 as libc::c_int;
                noout = 0 as libc::c_int;
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
    let mut args: Vec::<*mut libc::c_char> = Vec::new();
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
                (args.len() - 1) as libc::c_int,
                args.as_mut_ptr() as *mut *mut libc::c_char,
            ) as i32,
        )
    }
}
