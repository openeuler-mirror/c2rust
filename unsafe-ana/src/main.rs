use clap::Parser;
use rand::Rng;
use std::{cell::RefCell, collections::HashMap, env, fs, io::Write, path::Path, process::Command};
use syn::{
    __private::quote::quote,
    visit::{self, Visit},
};
use walkdir::WalkDir;

enum TP {
    Struct,
    Enum,
    Union,
}

thread_local! {
    static TYPENUM: RefCell<HashMap<String, (TP, u32)>> = RefCell::new(HashMap::new());
}

#[derive(Parser, Debug)]
struct Args {
    /// rust project directory
    #[arg(value_parser = is_dir)]
    directory: String,

    /// count type define
    #[arg(long, default_value_t = false)]
    count_type_define: bool,

    #[arg(long, default_value_t = false)]
    count_deref_rp: bool,
}

fn is_dir(s: &str) -> Result<String, String> {
    if !Path::new(s).exists() {
        return Err(format!("{} isn't a valid directory", s));
    }
    Ok(s.to_owned())
}

fn main() {
    let args = Args::parse();
    env::set_current_dir(&args.directory).expect("invalid dir");
    let mut func_num = 0;
    let mut unsafe_func_num = 0;
    let mut unsafe_line_num = 0;
    let mut total_line_num = 0;
    let mut safe_func_num = 0;
    let mut type_define_num = 0;
    let mut pointer_num = 0;
    let mut func_only_contain_rpderef_num = 0;
    let mut rng = rand::thread_rng();
    for entry in WalkDir::new("src").into_iter().filter_map(Result::ok) {
        let mut helper_func: syn::ItemFn = syn::parse_str("fn helper() {}").unwrap();
        let f_path = entry.path().to_string_lossy();
        if f_path.ends_with(".rs") {
            let input_code = fs::read_to_string(&*f_path).unwrap();
            total_line_num += input_code.bytes().filter(|c| *c == b'\n').count() + 1;
            let st = syn::parse_file(&input_code).unwrap();
            let mut visiter = Visitor::new(&mut helper_func);
            visiter.visit_file(&st);
            func_num += visiter.func_num;
            unsafe_func_num += visiter.unsafe_func_num;
            safe_func_num += visiter.safe_func_num;
            type_define_num += visiter.type_define_num;
            pointer_num += visiter.pointer_num;
            func_only_contain_rpderef_num += visiter.func_only_contain_rpderef_num;
        }
        let helper_code = syn::File {
            shebang: None,
            attrs: vec![],
            items: vec![syn::Item::Fn(helper_func)],
        };
        let filename = format!("temp-{}.rs", rng.gen_range(0..10000000));
        let mut helper_file = fs::File::create(&filename).unwrap();
        helper_file
            .write_all(quote!(#helper_code).to_string().as_bytes())
            .unwrap();
        drop(helper_file);
        Command::new("rustfmt").arg(&filename).status().unwrap();
        let format_code = fs::read_to_string(&filename).unwrap();
        unsafe_line_num += format_code.bytes().filter(|c| *c == b'\n').count() - 2;
        fs::remove_file(&filename).unwrap();
    }
    if args.count_type_define {
        println!("Type Define Number: {type_define_num}");
        println!("name,type,number");
        TYPENUM.with(|m| {
            m.borrow_mut().iter().for_each(|i| {
                println!(
                    "{},{},{}",
                    i.0,
                    match i.1 .0 {
                        TP::Union => "union",
                        TP::Enum => "enum",
                        TP::Struct => "struct",
                    },
                    i.1 .1
                );
            })
        });
    } else if args.count_deref_rp {
        println!("Function Only Contain Raw Pointer Deref Number: {func_only_contain_rpderef_num}");
    } else {
        println!("Total Function Number: {func_num}");
        println!("Unsafe Function Number: {unsafe_func_num}");
        println!("Safe Function Without Unsafe Block Number: {safe_func_num}");
        println!("Total Line Number: {total_line_num}");
        println!("Unsafe Line Number: {unsafe_line_num}");
        println!("Raw Pointer Define Number: {pointer_num}");
    }
}

struct Visitor<'a> {
    type_define_num: u32,
    func_num: u32,
    unsafe_func_num: u32,
    safe_func_num: u32,
    pointer_num: u32,
    exist_unsafe_block: bool,
    only_contain_rpderef: bool,
    func_only_contain_rpderef_num: u32,
    in_func: bool,
    helper_func: &'a mut syn::ItemFn,
}

impl<'a> Visitor<'a> {
    pub fn new(helper_func: &'a mut syn::ItemFn) -> Self {
        Self {
            type_define_num: 0,
            func_num: 0,
            unsafe_func_num: 0,
            safe_func_num: 0,
            pointer_num: 0,
            exist_unsafe_block: false,
            only_contain_rpderef: true,
            func_only_contain_rpderef_num: 0,
            in_func: false,
            helper_func,
        }
    }
}

impl Visit<'_> for Visitor<'_> {
    fn visit_item(&mut self, i: &'_ syn::Item) {
        match i {
            syn::Item::Union(item) => {
                self.type_define_num += 1;
                TYPENUM.with(|m| {
                    m.borrow_mut()
                        .entry(item.ident.to_string())
                        .or_insert((TP::Union, 0))
                        .1 += 1
                });
            }
            syn::Item::Enum(item) => {
                self.type_define_num += 1;
                TYPENUM.with(|m| {
                    m.borrow_mut()
                        .entry(item.ident.to_string())
                        .or_insert((TP::Enum, 0))
                        .1 += 1;
                })
            }
            syn::Item::Struct(item) => {
                self.type_define_num += 1;
                TYPENUM.with(|m| {
                    m.borrow_mut()
                        .entry(item.ident.to_string())
                        .or_insert((TP::Struct, 0))
                        .1 += 1;
                })
            }
            _ => {}
        }
        visit::visit_item(self, i);
    }

    fn visit_expr(&mut self, i: &'_ syn::Expr) {
        match i {
            syn::Expr::Unsafe(expr) => {
                self.exist_unsafe_block = true;
                if !quote!(#expr)
                    .to_string()
                    .replace(" ", "")
                    .replace("*mut", "")
                    .replace("*const", "")
                    .contains("*")
                {
                    self.only_contain_rpderef = false;
                }
                for stmt in &expr.block.stmts {
                    let mut nstmt = stmt.clone();
                    match &mut nstmt {
                        syn::Stmt::Local(_) => (),
                        syn::Stmt::Item(_) => (),
                        syn::Stmt::Expr(_, semi) => *semi = Some(syn::token::Semi::default()),
                        syn::Stmt::Macro(m) => m.semi_token = Some(syn::token::Semi::default()),
                    }
                    self.helper_func.block.stmts.push(nstmt);
                }
            }
            _ => (),
        }
        visit::visit_expr(self, i);
    }

    fn visit_item_fn(&mut self, i: &'_ syn::ItemFn) {
        self.in_func = true;
        self.func_num += 1;
        self.only_contain_rpderef = true;
        self.exist_unsafe_block = false;
        if i.sig.unsafety.is_some() {
            self.unsafe_func_num += 1;
            for stmt in &i.block.stmts {
                let mut nstmt = stmt.clone();
                match &mut nstmt {
                    syn::Stmt::Local(_) => (),
                    syn::Stmt::Item(_) => (),
                    syn::Stmt::Expr(_, semi) => *semi = Some(syn::token::Semi::default()),
                    syn::Stmt::Macro(m) => m.semi_token = Some(syn::token::Semi::default()),
                }
                self.helper_func.block.stmts.push(nstmt);
            }
        }
        visit::visit_item_fn(self, i);
        if i.sig.unsafety.is_none() && !self.exist_unsafe_block {
            self.safe_func_num += 1;
        }
        if self.exist_unsafe_block && self.only_contain_rpderef {
            self.func_only_contain_rpderef_num += 1;
        }
        self.in_func = false;
    }

    fn visit_pat_type(&mut self, i: &'_ syn::PatType) {
        let ty = i.ty.as_ref();
        if let syn::Type::Ptr(_) = ty {
            self.pointer_num += 1;
        } else if quote!(#ty).to_string().contains("Ptr") {
            self.pointer_num += 1;
        }
        visit::visit_pat_type(self, i);
    }

    // fn visit_local(&mut self, i: &'_ syn::Local) {
    //     if let syn::Pat::Type(pt) = &i.pat {
    //         if let syn::Type::Ptr(_) = pt.ty.as_ref() {
    //             self.pointer_num -= 1;
    //         }
    //     }
    //     visit::visit_local(self, i);
    // }

    // fn visit_return_type(&mut self, i: &'_ syn::ReturnType) {
    //     if let syn::ReturnType::Type(_, ty) = i {
    //         if let syn::Type::Ptr(_) = ty.as_ref() {
    //             // self.pointer_num += 1;
    //         }
    //     }
    //     visit::visit_return_type(self, i);
    // }
}
