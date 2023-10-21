import re
from pathlib import Path

import click
from loguru import logger

from scripts.utils import *


def lift_unsafe_assign_expr(file: Path, line_start: int, line_end: int):
    search_pattern_1 = r"\s*\(*\s*unsafe\s*\{\s*([^{}=\n;]+?)\s*\}\s*\)*\s*=\s*\(*\s*unsafe\s*\{\s*([^{}=\n;]+?)\s*\}\s*\)*\s*;"
    search_pattern_2 = r"\s*([^{}=\n;]+?)\s*=\s*\(*\s*unsafe\s*\{\s*([^{}=\n;]+?)\s*\}\s*\)*\s*;"
    search_pattern_3 = r"\s*\(*\s*unsafe\s*\{\s*([^{}=\n;]+?)\s*\}\s*\)*\s*=\s*([^{}=\n;]+?)\s*;"
    
    
    replace_pattern = r"unsafe { \1 = \2; }"
    
    with file.open("r") as f:
        lines = f.readlines()
    
    if line_end >= len(lines):
        logger.error(f"Line number {line_end} is out of range of file {file}")
        sys.exit(1)
        
    if line_start == line_end:
        fix_line = lines[line_start - 1]
        indent = len(fix_line) - len(fix_line.lstrip())
    else:
        indent = len(lines[line_start - 1]) - len(lines[line_start - 1].lstrip())
        fix_line = "".join([line.lstrip() for line in lines[line_start - 1:line_end]])

    mew_line = re.sub(search_pattern_1, replace_pattern, fix_line)
    
    if fix_line == mew_line:
        mew_line = re.sub(search_pattern_2, replace_pattern, fix_line)
        
    if fix_line == mew_line:    
        mew_line = re.sub(search_pattern_3, replace_pattern, fix_line)
    
    new_line = " " * indent + mew_line
    lines[line_start - 1] = new_line
    
    if line_start != line_end:    
        lines[line_start:line_end] = ["\n"] * (line_end - line_start)
        
    logger.debug(f"Change the error assigment({fix_line.strip()}) to correct one({new_line.strip()})")    

    with file.open("w") as f:
        f.writelines(lines)


def wrap_by_unsafe(file: Path, line_start: int, line_end: int):
    with file.open("r") as f:
        lines = f.readlines()
    
    if line_end >= len(lines):
        logger.error(f"Line number {line_end} is out of range of file {file}")
        sys.exit(1)
    
    if line_start == line_end:
        fix_line = lines[line_start - 1]
        indent = len(fix_line) - len(fix_line.lstrip())
    else:
        indent = len(lines[line_start - 1]) - len(lines[line_start - 1].lstrip())
        fix_line = "".join([line.lstrip() for line in lines[line_start - 1:line_end]])
        
    new_line = f"{' '* indent}unsafe {{ {fix_line} }}"
    lines[line_start - 1] = new_line
    
    if line_start != line_end:    
        lines[line_start:line_end] = ["\n"] * (line_end - line_start)
        
    logger.debug(f"Change the error assigment({fix_line.strip()}) to correct one({new_line.strip()})")    

    with file.open("w") as f:
        f.writelines(lines)   
            
            
def fix_unsafe_error(project: Path, errors: list):
    logger.info("Fixing unsafe error cause by type casting ...")
    for error in errors:
        if error["code"] == "E0271" or error["code"] == "E0070":
            logger.debug(f"Fixing error( {error['label']} ) in file {error['file']} at line {error['line_start']}:{error['line_end']} ...")
            lift_unsafe_assign_expr(project / error['file'], error['line_start'], error['line_end'])
        elif error["code"] == "E0133":
            logger.debug(f"Fixing error( {error['label']} ) in file {error['file']} at line {error['line_start']}:{error['line_end']} ...")
            wrap_by_unsafe(project / error['file'], error['line_start'], error['line_end'])


@click.command()
@click.argument("execute_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def cli(execute_path: Path):
    validate_res = validate_project_compilability(execute_path)
    if not validate_res["success"]:
        logger.error(f"Project {execute_path} is not compilable!")
        fix_unsafe_error(execute_path, validate_res["build_errors"])
    

if __name__ == "__main__":
    setup_logger(Path("/home/csslab/sandbox"))
    cli()


    