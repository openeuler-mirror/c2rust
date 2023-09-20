import platform
from pathlib import Path
from typing import Dict

import click

REPLACE_TYPES= {
    'libc::c_char': 'i8',
    'libc::c_uchar': 'u8',
    'libc::c_short': 'i16',
    'libc::c_ushort': 'u16',
    'libc::c_int': 'i32',
    'libc::c_uint': 'u32',
    'libc::c_longlong': 'i64',
    'libc::c_ulonglong': 'u64',
    'libc::c_long': 'i64',
    'libc::c_ulong': 'u64',
    'libc::c_schar': 'i8',
    'libc::c_double': 'f64'
}

def text_replace(target: Path, old_text: str, new_text: str):
    with target.open("r") as f:
        content = f.read()

    content = content.replace(old_text, new_text)

    with target.open("w") as f:
        f.write(content)


def replace_types(target: Path, types: Dict):
    # fix libc::c_char recognize as u8 bug is aarch64 platform
    if platform.machine() == "aarch64":
        types["libc::c_char"] = "u8"
    
    files = list(target.glob("**/*.rs"))
    for file in files:
        for old_type, new_type in types.items():
            text_replace(file, old_type, new_type)
    

@click.command()
@click.argument("execute_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def cli(execute_path: Path):
    replace_types(execute_path, REPLACE_TYPES)

if __name__ == "__main__":
    cli()
