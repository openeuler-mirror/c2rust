use serde_json::Value;
use std::{
    collections::HashMap,
    env, fs,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    process::{Command, Stdio},
};
use syn::{
    __private::quote::quote,
    visit_mut::{self, VisitMut},
};
use walkdir::WalkDir;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} [rust project directory]", args[0]);
        return;
    }
    env::set_current_dir(&args[1]).expect("invalid dir");
    remove_unsafe_sig();
    Command::new("cargo")
        .arg("fmt")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    fix();
    Command::new("cargo")
        .args(["fix", "--allow-no-vcs", "--allow-dirty", "--allow-staged"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    purge_unsafe_block();
    Command::new("cargo")
        .args(["fix", "--allow-no-vcs", "--allow-dirty", "--allow-staged"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
}

struct UnsafeFnHandler;

impl VisitMut for UnsafeFnHandler {
    fn visit_item_mut(&mut self, i: &mut syn::Item) {
        match i {
            syn::Item::Fn(func) => {
                if func.sig.variadic.is_none() {
                    func.sig.unsafety = None;
                }
            }
            _ => (),
        };
        visit_mut::visit_item_mut(self, i);
    }
}

fn remove_unsafe_sig() {
    let mut handler = UnsafeFnHandler;
    for entry in WalkDir::new("src").into_iter().filter_map(Result::ok) {
        let f_path = entry.path().to_string_lossy();
        if f_path.ends_with(".rs") {
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&*f_path)
                .unwrap();
            let mut input_code = String::new();
            file.read_to_string(&mut input_code).unwrap();
            let mut st = syn::parse_file(&input_code).expect(&format!("cannot parse {}", f_path));
            handler.visit_file_mut(&mut st);
            let new_st = quote!(#st);
            file.seek(SeekFrom::Start(0)).unwrap();
            file.set_len(0).unwrap();
            file.write_all(new_st.to_string().as_bytes()).unwrap();
            file.flush().unwrap();
        }
    }
}

fn fix() {
    fn process_json(json_objs: Value) -> Result<(String, usize, usize), ()> {
        let msg = json_objs
            .as_object()
            .ok_or(())?
            .get("message")
            .ok_or(())?
            .as_object()
            .ok_or(())?;
        let code = msg
            .get("code")
            .ok_or(())?
            .as_object()
            .ok_or(())?
            .get("code")
            .ok_or(())?
            .as_str()
            .ok_or(())?;
        if code != "E0133" {
            return Err(());
        }
        let span = msg
            .get("spans")
            .ok_or(())?
            .as_array()
            .ok_or(())?
            .get(0)
            .ok_or(())?
            .as_object()
            .ok_or(())?;

        let textobj = span
            .get("text")
            .ok_or(())?
            .as_array()
            .ok_or(())?
            .get(0)
            .ok_or(())?
            .as_object()
            .ok_or(())?;
        let textstart = textobj
            .get("highlight_start")
            .ok_or(())?
            .as_u64()
            .ok_or(())? as usize;
        let textend = textobj.get("highlight_end").ok_or(())?.as_u64().ok_or(())? as usize;
        let text = textobj.get("text").ok_or(())?.as_str().ok_or(())?;
        if text[textstart - 1..textend - 1].starts_with("match") {
            return Err(());
        }

        Ok((
            span.get("file_name")
                .ok_or(())?
                .as_str()
                .ok_or(())?
                .to_owned(),
            span.get("byte_start").ok_or(())?.as_u64().ok_or(())? as usize,
            span.get("byte_end").ok_or(())?.as_u64().ok_or(())? as usize,
        ))
    }
    let mut child = Command::new("cargo")
        .env("RUSTFLAGS", "-Awarnings")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .args(["check", "--message-format", "json"])
        .spawn()
        .unwrap();
    let output = BufReader::new(child.stdout.take().unwrap());
    let deserializer = serde_json::Deserializer::from_reader(output);
    let iterator = deserializer.into_iter::<serde_json::Value>();
    let mut filename2spans = HashMap::new();
    for item in iterator {
        let obj = item.unwrap();
        if let Ok(res) = process_json(obj) {
            filename2spans
                .entry(res.0)
                .or_insert(vec![])
                .push((res.1, res.2));
        }
    }
    for (_, spans) in &mut filename2spans {
        spans.sort_unstable_by_key(|x| x.0);
        let mut old_spans = Vec::with_capacity(spans.len());
        std::mem::swap(spans, &mut old_spans);
        let mut p1 = 0;
        for span in old_spans {
            if span.0 < p1 {
                p1 = p1.max(span.1);
                spans.last_mut().unwrap().1 = p1;
            } else {
                p1 = span.1;
                spans.push(span);
            }
        }
    }
    for (filename, spans) in filename2spans {
        let mut idx = 0;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&filename)
            .unwrap();
        let mut old_code = String::new();
        file.read_to_string(&mut old_code).unwrap();
        let mut new_code = String::with_capacity(old_code.len());
        for span in spans {
            new_code += &old_code[idx..span.0];
            new_code = new_code + "(unsafe { " + &old_code[span.0..span.1] + " })";
            idx = span.1;
        }
        new_code += &old_code[idx..];
        file.seek(SeekFrom::Start(0)).unwrap();
        file.set_len(0).unwrap();
        file.write_all(new_code.as_bytes()).unwrap();
        file.flush().unwrap();
    }
}

fn purge_unsafe_block() {
    fn process_json(json_objs: Value) -> Result<(String, usize, usize), ()> {
        let msg = json_objs
            .as_object()
            .ok_or(())?
            .get("message")
            .ok_or(())?
            .as_object()
            .ok_or(())?;
        let code = msg
            .get("code")
            .ok_or(())?
            .as_object()
            .ok_or(())?
            .get("code")
            .ok_or(())?
            .as_str()
            .ok_or(())?;
        if code != "unused_unsafe" {
            return Err(());
        }
        let span = msg
            .get("spans")
            .ok_or(())?
            .as_array()
            .ok_or(())?
            .get(0)
            .ok_or(())?
            .as_object()
            .ok_or(())?;

        Ok((
            span.get("file_name")
                .ok_or(())?
                .as_str()
                .ok_or(())?
                .to_owned(),
            span.get("byte_start").ok_or(())?.as_u64().ok_or(())? as usize,
            span.get("byte_end").ok_or(())?.as_u64().ok_or(())? as usize,
        ))
    }

    let mut child = Command::new("cargo")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .args(["check", "--message-format", "json"])
        .spawn()
        .unwrap();
    let output = BufReader::new(child.stdout.take().unwrap());
    let deserializer = serde_json::Deserializer::from_reader(output);
    let iterator = deserializer.into_iter::<serde_json::Value>();
    let mut filename2spans = HashMap::new();
    for item in iterator {
        let obj = item.unwrap();
        if let Ok(res) = process_json(obj) {
            filename2spans
                .entry(res.0)
                .or_insert(vec![])
                .push((res.1, res.2));
        }
    }
    for (_, spans) in &mut filename2spans {
        spans.sort_unstable_by_key(|x| x.0);
        let mut old_spans = Vec::with_capacity(spans.len());
        std::mem::swap(spans, &mut old_spans);
        let mut p1 = 0;
        for span in old_spans {
            if span.0 < p1 {
                p1 = p1.max(span.1);
                spans.last_mut().unwrap().1 = p1;
            } else {
                p1 = span.1;
                spans.push(span);
            }
        }
    }
    for (filename, spans) in filename2spans {
        let mut idx = 0;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&filename)
            .unwrap();
        let mut old_code = String::new();
        file.read_to_string(&mut old_code).unwrap();
        let mut new_code = String::with_capacity(old_code.len());
        for span in spans {
            new_code += &old_code[idx..span.0];
            idx = span.1;
        }
        new_code += &old_code[idx..];
        file.seek(SeekFrom::Start(0)).unwrap();
        file.set_len(0).unwrap();
        file.write_all(new_code.as_bytes()).unwrap();
        file.flush().unwrap();
    }
}
