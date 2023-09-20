import sys
import json
import shutil 
from pathlib import Path
from datetime import datetime
from typing import Dict

import toml
import click
from loguru import logger
from plumbum import local


BASE = Path(__file__).parent.resolve()
with (BASE / "config.toml").open("r") as f:
    CONFIG = toml.load(f)
RESULT = BASE / CONFIG["project"]["results-path"]

def setup_logger():
    log_folder = Path(BASE / "logs")
    log_folder.mkdir(exist_ok=True)
    
    logger.remove()
    logger.add(log_folder / "run.log", format="{time:YYYY-MM-DD HH:mm:ss} {level} {message}", 
               backtrace=True, diagnose=True, rotation="1 day", level="DEBUG")
    logger.add(sys.stdout, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level} {message}</level>",  
               level="INFO", colorize=True ) 

def execute(cmd, path=BASE, dismiss_error=False):
    logger.info(f"Executing command: {cmd} ... ")
    tool, args = cmd.split(" ", 1)
    with local.cwd(path):
        try:
            result = local[tool](args.split(" "))
        except Exception as e:
            if dismiss_error:
                return ""
            logger.exception(f"Executing Command failed!" )
            sys.exit(1)
        
    return result


def resolve_imports(input: Path,  pre_script: Path, inplace=False):
    if inplace:
        output = input
    else:
        output = input.parent / "P2_after_resolve_imports"
        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(input, output)
        
    logger.info(f"Start resolve imports for {output} | inplace: {inplace}")
    logger.info(f"run the pre-process script({pre_script}) ...")
    execute(f"python3 {pre_script} {output}", output)
    logger.success("Execute pre-process success!")
    
    logger.info(f"Start build the {output} to generate the deps ...")
    execute(f"cargo build", output)
    logger.success(f"build {output} success!")
        
    imports_resolver = BASE / CONFIG["project"]["target-path"] / "safer-c2rust" / "import-resolver"
    execute(f"{imports_resolver} {output / 'lib.rs'} -L {output / 'target' / 'debug' / 'deps'}", output)
    logger.success(f"resolve imports success! result: {output}")
    

def resolve_lifetime(input: Path, pre_script: Path, inplace=False):
    if inplace:
        output = input
    else:
        output = input.parent / "P3_after_resolve_lifetime"
        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(input, output)
        
    logger.info(f"Start resolve lifetime for {input} | inplace: {inplace}")
    logger.info(f"run the pre-process script({pre_script}) ...")
    execute(f"python3 {pre_script} {output}", output)
    logger.success("Execute pre-process success!")
    
    logger.info(f"Start build the {output} to generate the deps ...")
    execute(f"cargo build", output)
    logger.success(f"build {output} success!")
        
    lifetime_resolver = BASE / CONFIG["project"]["target-path"] / "safer-c2rust" / "lifetime-resolver"
    execute(f"{lifetime_resolver} -f --merge-field-lifetimes {output / 'lib.rs'} -L {output / 'target' / 'debug' / 'deps'}", output, dismiss_error=True)
    logger.success(f"resolve lifetime success! result: {output}")
    

def fix_unsafe(input: Path, pre_script: Path, inplace=False):
    if inplace:
        output = input
    else:
        output = input.parent / "P4_result"
        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(input, output)
        
    logger.info(f"Start fix unsafe for {input} | inplace: {inplace}")
    logger.info(f"run the pre-process script({pre_script}) ...")
    execute(f"python3 {pre_script} {output}", output)
    logger.success("Execute pre-process success!")
    
    lifetime_resolver = BASE / CONFIG["project"]["target-path"] / "safer-c2rust" / "unsafe-fixer"
    execute(f"{lifetime_resolver} {output}", output)
    logger.success(f"resolve imports success! result: {output}")
    

def parse_safe_analysis_result(result: Path):
    logger.info(f"Start analysis the safety performance of : ({result}) ...")
    safe_analyzer = BASE / CONFIG["project"]["target-path"] / "safe-analyzer" / "safe-analyzer"
    
    # analysis the type define
    logger.info(f"Start analysis the type define of : ({result}) ...")
    type_define = execute(f"{safe_analyzer} --count-type-define {result}", result.parent)
    type_define = type_define.splitlines()
    total_title, total_number = type_define[0].split(":")
    type_define_res = {total_title.strip(): total_number.strip()}
    type_define_details = []
    for line in type_define[2:]:
        _name, _type, _count = line.split(",")
        type_define_details.append({"name": _name.strip(), "type": _type.strip(), "count": _count.strip()})
        
    type_define_res["details"] = type_define_details
    logger.success(f"Analysis the type define of {result} success!")
    
    # analysis the unsafe block/function and the raw pointers
    logger.info(f"Start analysis the unsafe block/function and the raw pointers of : ({result}) ...")
    unsafe = execute(f"{safe_analyzer} {result}", result.parent).splitlines()
    unsafe_res = {}
    for line in unsafe:
        name, value = line.split(":")
        unsafe_res[name.strip()] = int(value.strip())
    
    deref_rp = execute(f"{safe_analyzer} --count-deref-rp {result}", result.parent).splitlines()
    deref_rp_title, deref_rp_number = deref_rp[0].split(":")
    unsafe_res[deref_rp_title.strip()] = int(deref_rp_number.strip())
    logger.success(f"Analysis the unsafe block/function and the raw pointers of {result} success!")
    
    return {"type define result": type_define_res, "unsafe result": unsafe_res}
    



@click.group(chain=True)
@click.option("--work_dir", "-w", type=click.Path(exists=False, file_okay=False, writable=True, path_type=Path),
              default=RESULT, help="The work directory", show_default=f"{RESULT}/<project-name>_<datetime>")
@click.pass_context
def cli(ctx, work_dir: Path):
    ctx.ensure_object(dict)
    ctx.obj["work_dir"] = work_dir
    work_dir.mkdir(parents=True, exist_ok=True)


@cli.command()
@click.option("--c_project_path", "-c", type=click.Path(exists=True, file_okay=False, path_type=Path, resolve_path=True))
@click.option("--mode", type=click.Choice(["auto","script"], case_sensitive=False), default="auto", show_default=True,
              help="""Choose the mode to do the original c2rsut translate,
                    if use auto mode, you need to specify the compile_commands.json generate method by `--gencc`; 
                    if use script mode, you need to specify the script path by `--script`.""")
@click.option("--gencc", type=click.Choice(["cmake", "makefile"], case_sensitive=False), default="cmake", show_default=True,
              help="""Choose the method to generate compile_commands.json, if use script, you should set the `--mode` to AUTO.""")
@click.option("--script", type=click.Path(exists=True, dir_okay=False, path_type=Path), show_default=True,
              help="""The shell or python script to do the c2rust translation, you should set the `--mode` to SCRIPT, 
                  metion that the script should take two arguments, the first is the c project path, the second is the output path.""")
@click.pass_context
def c2rust(ctx, c_project_path: Path, mode: str, gencc: str, script: Path):
    work_dir = ctx.obj["work_dir"].resolve()
    
    # if output hasn't defined, create a folder automatically
    if work_dir == RESULT:
        work_dir = work_dir / f"{c_project_path.stem}_{datetime.now().strftime('%y%m%d_%H%M%S')}"
        ctx.obj["work_dir"] = work_dir
    
    if work_dir.exists():
        shutil.rmtree(work_dir)
    logger.info(f"Crate project work directory: {work_dir}")
    work_dir.mkdir(parents=True)
        
    c_project = work_dir / "P0_original"
    logger.info(f"Copy the original c project to work directory as {c_project} ...")
    shutil.copytree(c_project_path, c_project)
    
    after_translate = work_dir / "P1_after_c2rust"
    after_translate.mkdir(parents=True, exist_ok=True)
    
    if mode == "script":
        if script is None:
            logger.error("You should specify the script path by `--script`")
            sys.exit(1)
            
        script = script.resolve()
        
        logger.info("Start the original c2rsut translate by SCRIPT mode ...")
        if script.suffix == ".py":
            execute(f"python3 {script} {c_project} {after_translate}", work_dir)
        elif script.suffix == ".sh":
            execute(f"{script} {c_project} {after_translate}", work_dir)
        else:
            logger.error("The script should be a python or shell script!")
            sys.exit(1)
    else:
        logger.info("Start the original c2rsut translate by AUTO mode ...")
        logger.info(f"Generate compile_commands.json by {mode} ...")
        if gencc == "cmake":
            cmake_cache = c_project / "CMakeCache.txt"
            if cmake_cache.exists():
                cmake_cache.unlink()
            execute("cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON", c_project)
        else:
            execute("intercept-build make", c_project)
            
        compile_commands = c_project / "compile_commands.json"    
        logger.success(f"Generate {compile_commands}(size: {compile_commands.stat().st_size}) success!")
            
        c2rust = BASE / "bin" / "c2rust" / "c2rust"
        
        logger.info("Start the original c2rsut translate ...")
        execute(f"{c2rust} transpile {compile_commands} -e -o {after_translate}")
        
    logger.success(f"Translate by original c2rsut success! The result is in {after_translate}")
    

@cli.command()
@click.option("--is_resolve_imports", "-im", type=bool, default=True, help="Turn the imports resolver on", show_default=True)
@click.option("--resolve_imports_pre_script",  type=click.Path(exists=True, dir_okay=False, path_type=Path), 
              default= BASE / "scripts" / "pre_resolve_imports.py", show_default=True,
              help="Specify the pre-process script of imports resolver")
@click.option("--is_resolve_lifetime", "-lt", type=bool, default=True, help="Turn the lifetime resolver on", show_default=True)
@click.option("--resolve_lifetime_pre_script",  type=click.Path(exists=True, dir_okay=False, path_type=Path), 
              default= BASE / "scripts" / "pre_resolve_lifetime.py", show_default=True,
              help="Specify the pre-process script of lifetime resolver")
@click.option("--is_fix_unsafe", "-us", type=bool, default=True, help="Turn the unsafe fixer on")
@click.option("--fix_unsafe_pre_script",  type=click.Path(exists=True, dir_okay=False, path_type=Path), 
              default= BASE / "scripts" / "pre_unsafe_fix.py", show_default=True,
              help="Specify the pre-process script of unsafe fixer")
@click.pass_context
def safer(ctx, is_resolve_imports, resolve_imports_pre_script, is_resolve_lifetime, resolve_lifetime_pre_script, 
          is_fix_unsafe, fix_unsafe_pre_script):
    # if output hasn't defined, use c2rust's output path
    work_dir = ctx.obj["work_dir"].resolve()
    
    logger.info(f"Start the safer-c2rust processes ...")
    if is_resolve_imports:
        if not (work_dir / "P1_after_c2rust").is_dir():
            logger.error("You should has the original c2rust result in the work directory before do the imports resolve!")
            sys.exit(1)
        resolve_imports(work_dir / "P1_after_c2rust", resolve_imports_pre_script)
    
    if is_resolve_lifetime:
        if not (work_dir / "P2_after_resolve_imports").is_dir():
            logger.error("You should has the imports resolved result in the work directory before do the lifetime resolve!")
            sys.exit(1)
        resolve_lifetime(work_dir / "P2_after_resolve_imports", resolve_lifetime_pre_script)
    
    if is_fix_unsafe:
        if not (work_dir / "P3_after_resolve_lifetime").is_dir():
            logger.error("You should has the lifetime resolved result in the work directory before do the unsafe fix!")
            sys.exit(1)
        fix_unsafe(work_dir / "P3_after_resolve_lifetime", fix_unsafe_pre_script)
    
    result = work_dir / "P4_result"
    
    logger.info(f"Re-build the result({result}) to verify ....")
    execute("cargo build", result)
    logger.success(f"build the result({result}) success!")
    execute("cargo clean", result)
    logger.success(f"Successfully finished the safer-c2rust processes!")
    
    
@cli.command()
@click.pass_context # type: ignore
def stat(ctx):
    work_dir = ctx.obj["work_dir"].resolve()
    needed_dirs = ["P1_after_c2rust", "P4_result"]
    
    stat_detail = {}
    for needed_dir in needed_dirs:
        result_dir = work_dir / needed_dir
        if not result_dir.is_dir():
            logger.error(f"To get the full statistics result, you need {needed_dirs} in the work directory!")
            sys.exit(1)

        stat_detail[needed_dir] = parse_safe_analysis_result(result_dir)
    
    stat_detail_file = work_dir / "report_detail.json"
    with stat_detail_file.open("w") as f:
        json.dump(stat_detail, f, indent=4)
    logger.success(f"Successfully write the detail statistics result to {stat_detail_file}")
    
    stat_summary = {}
    before = int(stat_detail["P1_after_c2rust"]["type define result"]["Type Define Number"])
    after = int(stat_detail["P4_result"]["type define result"]["Type Define Number"])
    if before == 0:
        result = "100%"
    else:
        result = (before - after) / before
        result = f"{result*100:.2f}%"
        
    stat_summary["重复类型定义去除率"] = result
    
    before = stat_detail["P1_after_c2rust"]["unsafe result"]["Safe Function Without Unsafe Block Number"]
    func_contains_raw_pointer_before = stat_detail["P4_result"]["unsafe result"]["Function Only Contain Raw Pointer Deref Number"]
    after = stat_detail["P4_result"]["unsafe result"]["Safe Function Without Unsafe Block Number"]
    if func_contains_raw_pointer_before == 0:
        result = "null"
    else:
        result = (after - before) / func_contains_raw_pointer_before
        result = f"{result*100:.2f}%"
    stat_summary["使用裸指针导致的不安全函数减少比例"] = result
    
    before = stat_detail["P1_after_c2rust"]["unsafe result"]["Raw Pointer Define Number"]
    after = stat_detail["P4_result"]["unsafe result"]["Raw Pointer Define Number"]
    if before == 0:
        result = "null"
    else:
        result = (before - after) / before
        result = f"{result*100:.2f}%"
    
    stat_summary["裸指针声明数量减少比例"] = result
    
    func_number = stat_detail["P4_result"]["unsafe result"]["Total Function Number"]
    unsafe_func_number = stat_detail["P4_result"]["unsafe result"]["Unsafe Function Number"]
    result = (func_number - unsafe_func_number) / func_number
    stat_summary["安全函数占比"] = f"{result*100:.2f}%"
    
    line_number = stat_detail["P4_result"]["unsafe result"]["Total Line Number"]
    unsafe_line_number = stat_detail["P4_result"]["unsafe result"]["Unsafe Line Number"]
    result = (line_number - unsafe_line_number) / line_number
    stat_summary["安全代码行数占比"] = f"{result*100:.2f}%"
    
    logger.info(f"Statistics result: {stat_summary}")
    
    stat_summary_file = work_dir / "report_summary.json"
    with stat_summary_file.open("w", encoding='utf-8') as f:
        json.dump(stat_summary, f, indent=4, ensure_ascii=False)
    logger.success(f"Successfully write the summary statistics result to {stat_summary_file}")
    

if __name__ == "__main__":
    setup_logger()
    cli(obj={})
