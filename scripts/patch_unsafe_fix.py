import re
from pathlib import Path

import click
from loguru import logger

from scripts.utils import *


def lift_unsafe_assign_expr(file: Path, line_no: int):
    search_pattern = r"\s*([^{}=\n;]+?)\s*=\s*\(*\s*unsafe\s*\{\s*([^{}=\n;]+?)\s*\}\s*\)*\s*;"
    replace_pattern = r"unsafe { \1 = \2; }"
    
    with file.open("r") as f:
        lines = f.readlines()
    
    if line_no >= len(lines):
        logger.error(f"Line number {line_no} is out of range of file {file}")
        sys.exit(1)
    
    fix_line = lines[line_no - 1]
    indent = len(fix_line) - len(fix_line.lstrip())
    
    mew_line = re.sub(search_pattern, replace_pattern, fix_line)
    new_line = " " * indent + mew_line
    lines[line_no - 1] = new_line
    logger.debug(f"Change the error assigment({fix_line.strip()}) to correct one({new_line.strip()})")    

    with file.open("w") as f:
        f.writelines(lines)

            
def fix_unsafe_error_cause_by_type_cast(project: Path):
    logger.info("Fixing unsafe error cause by type casting ...")
    build_info = exec_cmd("cargo build", project, env={"RUSTFLAGS": "-Awarnings"}, dismiss_error=True)
    build_errors = parse_cagro_build_errors(build_info)
    
    for build_error in build_errors:
        if build_error["error"].startswith("error[E0271]"):
            file_path = project / build_error["file"]
            logger.debug(f"Fixing unsafe assign expression in file {file_path} at line {build_error['line_no']} ...")
            lift_unsafe_assign_expr(file_path, build_error["line_no"])


@click.command()
@click.argument("execute_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def cli(execute_path: Path):
    fix_unsafe_error_cause_by_type_cast(execute_path)


if __name__ == "__main__":
    # setup_logger(Path("/home/csslab/sandbox"))
    cli()


    