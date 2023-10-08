import random
import re
import string
from pathlib import Path

import click
from loguru import logger

from scripts.utils import *


def fix_dup_symbol_errors(project: Path):
    logger.info("Fixing duplicated symbol errors ...")
    build_info = exec_cmd("cargo build", project, env={"RUSTFLAGS": "-Awarnings"}, dismiss_error=True)
    build_errors = parse_cagro_build_errors(build_info)
    
    for build_error in build_errors:
        
        match = re.search(r"error: symbol `([^`]*)` is already defined", build_error["error"])
        if not match:
            continue
        
        dup_symbol = match.group(1)
        logger.debug(f"Find duplicated symbol {dup_symbol} in file {build_error['file']}")
        
        random_id = ''.join(random.choice(string.ascii_uppercase) for _ in range(4))
        
        file_text_replace(project / build_error["file"], dup_symbol, f"{dup_symbol}_{random_id}")
        logger.debug(f"Replace all {dup_symbol} with {dup_symbol}_{random_id} in file {build_error['file']}")


def fix_type_errors(project: Path):
    logger.info("Fixing type errors ...")
    build_info = exec_cmd("cargo build", project, env={"RUSTFLAGS": "-Awarnings"}, dismiss_error=True)
    build_errors = parse_cagro_build_errors(build_info)
    
    for build_error in build_errors:
        if not build_error["error"].startswith("error[E0308]"):
            continue
        
        match = re.search(r'expected `(\w+)`, found `(\w+)`', build_error["error_detail"])
        if not match:
            continue
        
        expected_type, found_type = match.group(1), match.group(2)
        logger.debug(f"Find type error: expected {expected_type}, found {found_type} in file {build_error['file']}")
        
        file_path = project / build_error["file"]
        with file_path.open("r") as f:
            lines = f.readlines()
        
        error_line = lines[build_error["line_no"] - 1]
        error_start_col_no = build_error["col_no"] - 1
        fixed_line = error_line[0:error_start_col_no] + error_line[error_start_col_no:].replace(found_type, expected_type, 1)
            
        lines[build_error["line_no"] - 1] = fixed_line
        logger.debug(f"Change the error line({error_line.strip()}) to correct one ({fixed_line.strip()}) in file ({build_error['file']} | {build_error['line_no']})")
        
        with file_path.open("w") as f:
            f.writelines(lines)


@click.command()
@click.argument("execute_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def cli(execute_path: Path):
    fix_type_errors(execute_path)
    fix_dup_symbol_errors(execute_path)


if __name__ == "__main__":
    setup_logger(Path("/home/csslab/sandbox"))
    cli()
    
    # logger.remove()
    # logger.add(sys.stdout, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level} {message}</level>",  
    #            level="DEBUG", colorize=True ) 
    # fix_type_errors(Path("/home/csslab/c2rust/results/libarchive_231007_171144/P1_after_c2rust"))