import os
import re
import sys

pattern_1 = r"let\s+ref\s+mut\s+(\w+)\s*=\s*([\s\S]*?);"
pattern_2 = r"let\s+ref\s+(\w+)\s*=\s*(.*);"

def replace_text(dir_path, old_text, new_text):
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if os.path.splitext(file)[1] == '.rs':
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()
                content = re.sub(old_text, new_text, content)
                with open(file_path, 'w') as f:
                    f.write(content)

def replace_pattern_1(dir_path):
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if os.path.splitext(file)[1] == '.rs':
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()
                result = re.sub(pattern_1, r"let \1 = &mut (\2);", content)
                with open(file_path, 'w') as f:
                    f.write(result)

def replace_pattern_2(dir_path):
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if os.path.splitext(file)[1] == '.rs':
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()
                result = re.sub(pattern_2, r"let \1 = &(\2);", content)
                with open(file_path, 'w') as f:
                    f.write(result)

def main():
    cwd = os.getcwd()
    work_dir = cwd + '/rewrite-workspace/' + sys.argv[1]
    rewrite_invocation = cwd + '/rewrite-workspace/' + sys.argv[1] + '/lib.rs -L all=' + cwd + '/rewrite-workspace/' + sys.argv[1] + '/target/debug/deps'
    with open("rewrite-invocations/" + sys.argv[1], "w") as file:
        file.write(rewrite_invocation)

    replace_text(work_dir, 'libc::c_char', 'i8')
    replace_text(work_dir, 'libc::c_uchar', 'u8')
    replace_text(work_dir, 'libc::c_short', 'i16')
    replace_text(work_dir, 'libc::c_ushort', 'u16')
    replace_text(work_dir, 'libc::c_int', 'i32')
    replace_text(work_dir, 'libc::c_uint', 'u32')
    replace_text(work_dir, 'libc::c_longlong', 'i64')
    replace_text(work_dir, 'libc::c_ulonglong', 'u64')
    replace_text(work_dir, 'libc::c_long', 'i64')
    replace_text(work_dir, 'libc::c_ulong', 'u64')
    replace_text(work_dir, 'libc::c_schar', 'i8')
    replace_text(work_dir, 'libc::c_double', 'f64')

    replace_pattern_1(work_dir)
    replace_pattern_2(work_dir)


if __name__ == "__main__":
    main()