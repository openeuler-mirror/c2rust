import sys
from pathlib import Path
from typing import List

import click
from loguru import logger

IMPORTS = [
    "#![feature(rustc_private)]",
    "#![feature(const_fn_fn_ptr_basics)]",
    "#![feature(const_mut_refs)]"
]

def insert_import(lib_file: Path, imports: List[str]):
    # instert the import line to the lib.rs file
    with lib_file.open("r") as f:
        content = f.readlines()
    
    for import_line in imports:
        if f"{import_line}\n" in content:
            logger.debug(f"Already has {import_line} in {lib_file}")
            continue
        
        logger.debug(f"Insert {import_line} to {lib_file}")
        content.insert(0, import_line + "\n")
    
    with lib_file.open("w") as f:
        f.writelines(content)

@click.command()
@click.argument("execute_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def cli(execute_path: Path):
    logger.remove()
    logger.add(sys.stdout, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level} {message}</level>", 
               level="INFO", colorize=True)

    insert_import(execute_path / "lib.rs", IMPORTS)

if __name__ == "__main__":
    
    cli()
    
