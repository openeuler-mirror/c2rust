import re
import sys
import toml
from pathlib import Path
from typing import Dict, List
from functools import lru_cache

from plumbum import ProcessExecutionError, ProcessTimedOut, local
from loguru import logger


def file_text_replace(target: Path, old_text: str, new_text: str):
    with target.open("r") as f:
        content = f.read()

    content = content.replace(old_text, new_text)

    with target.open("w") as f:
        f.write(content) 
    
        
def file_text_replace_by_pattern(target: Path, search_pattern: str, replace_pattern: str):
    with target.open("r") as f:
        content = f.read()
    
    content = re.sub(search_pattern, replace_pattern, content)

    with target.open("w") as f:
        f.write(content)

        
def setup_logger(log_folder: Path):
    log_folder.mkdir(exist_ok=True)
    
    logger.remove()
    logger.add(log_folder / "run.log", format="{time:YYYY-MM-DD HH:mm:ss} {level} {message}", 
               backtrace=True, diagnose=True, rotation="1 day", level="DEBUG")
    logger.add(sys.stdout, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level} {message}</level>",  
               level="INFO", colorize=True ) 

        
def exec_cmd(cmd: str, path :Path, env: Dict = {}, dismiss_error=False, timeout=None):
    logger.debug(f"Executing command: {cmd} ... ")
    pattern = r'\s+(?=(?:[^"]*"[^"]*")*[^"]*$)'
    sub_cmds = re.split(pattern, cmd)
    sub_cmds = [ sub_cmd.replace('"', '') for sub_cmd in sub_cmds if sub_cmd != ""]
    tool = local[sub_cmds[0]]
    with local.cwd(path):
        try:
            with local.env(**env):
                if len(sub_cmds) == 1:
                    result = tool(timeout=timeout)
                else:
                    result = tool(sub_cmds[1:], timeout=timeout)
        except ProcessExecutionError as e:
            if dismiss_error:
                return e.stderr
            logger.exception(f"Executing Command({cmd}) failed!" )
            sys.exit(1)
        except ProcessTimedOut as e:
            if dismiss_error:
                return "timeout"
            
            logger.exception(f"Executing Command({cmd}) timeout!" )
            sys.exit(1)
        
    return result

    
def parse_cagro_build_errors(build_output) -> List:
    build_errors = []
    
    lines = build_output.splitlines()
    if not lines:
        logger.info(f"Build info is empty!")
        return build_errors
    
    logger.info(f"Parsing build info ... ")
    
    for idx, line in enumerate(lines):
        if idx == len(lines) - 1:
            break
        
        build_error = {}
        line = line.strip()
    
        error_info_line = lines[idx+1].strip()
        if line.startswith("error") and error_info_line.startswith("-->"):
            build_error["error"] = line
            build_error["file"], err_line_no, err_col_no  = error_info_line[3:].strip().split(":")
            build_error["line_no"] = int(err_line_no)
            build_error["col_no"] = int(err_col_no)
            
            error_detail_line = lines[idx+4].lstrip("|").strip()
            match = re.search(r"\^+ (.*)$", error_detail_line)
            if match:
                build_error["error_detail"] = match.group(1)
            else:
                build_error["error_detail"] = ""
            
            build_errors.append(build_error)
            logger.debug(f"Find build error: {build_error}")
            
        
    return build_errors


@lru_cache(maxsize=1)
def get_configs(config_file: Path):
    logger.debug(f"Loading config file({config_file})")
    with config_file.open("r") as f:
        config = toml.load(f)
    logger.debug(f"Config: {config}")
    return config

    
if __name__ == "__main__":
    setup_logger(Path("/home/csslab/sandbox"))
    res = exec_cmd("cargo build", Path("/home/csslab/c2rust/results/libarchive_231007_171144/P1_after_c2rust"), 
                   env={"RUSTFLAGS": "-Awarnings"}, dismiss_error=True)
    errors = parse_cagro_build_errors(res)
    for error in errors:
        logger.info(error)
    

    #logger.info(exec_cmd("ls -l", Path("results/libxml2-2.9_230924_161038/P3_after_resolve_lifetime/")))