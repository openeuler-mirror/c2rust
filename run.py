import sys
import json
import shutil 
from pathlib import Path
from datetime import datetime

import click
from loguru import logger

from scripts.utils import exec_cmd, get_configs, validate_project_compilability
from scripts.patch_unsafe_fix import fix_unsafe_error
from scripts.patch_compile_commands import fix_oe_gcc_args
from scripts.patch_c2rust_results import fix_dup_symbol_errors, fix_type_errors

logger.remove()
logger.add(sys.stdout, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level} {message}</level>",
           level="INFO", colorize=True ) 

BASE = Path(__file__).parent.resolve()
CONFIG = get_configs(BASE / "config.toml")
RESULT = BASE / CONFIG["project"]["results-path"]


def resolve_imports(input: Path, rollback=False):
    output = input.parent / "P2_after_resolve_imports"
    pre_script = BASE / "scripts" / "pre_resolve_imports.py"
    
    shutil.rmtree(output, ignore_errors=True)
    shutil.copytree(input, output)
            
    logger.info(f"Start resolve imports for {output} ...")
    logger.info(f"run the pre-process script({pre_script}) ...")
    exec_cmd(f"python3 {pre_script} {output}", output)
    
    logger.info(f"Start build the {output} to generate the deps ...")
    exec_cmd(f"cargo build", output, env={"RUSTFLAGS": "-Awarnings"})
    
    logger.info(f"Start resolve imports ...")
    imports_resolver = BASE / CONFIG["project"]["target-path"] / "safer-c2rust" / "import-resolver"
    exec_cmd(f"{imports_resolver} {output / 'lib.rs'} -L {output / 'target' / 'debug' / 'deps'}", output)
    
    validate_res = validate_project_compilability(output)
    if validate_res["success"]:
        logger.success(f"resolve imports success! result: {output}")
        return
    
    if not rollback:
        logger.error(f"resolve imports failed! result: {output}")
        exit(1)
        
    logger.info(f"resolve imports failed, Roll back to before optimization!")
    shutil.rmtree(output)
    shutil.copytree(input, output)
    

def resolve_lifetime(input: Path, rollback=False):
    output = input.parent / "P3_after_resolve_lifetime"
    pre_script = BASE / "scripts" / "pre_resolve_lifetime.py"
    
    shutil.rmtree(output, ignore_errors=True)
    shutil.copytree(input, output)
        
    logger.info(f"Start resolve lifetime for {input} ... ")
    logger.info(f"run the pre-process script({pre_script}) ...")
    exec_cmd(f"python3 {pre_script} {output}", output)
    
    logger.info(f"Start build the {output} to generate the deps ...")
    exec_cmd(f"cargo build", output, env={"RUSTFLAGS": "-Awarnings"})
        
    logger.info(f"Start resolve lifetime ...")
    lifetime_resolver = BASE / CONFIG["project"]["target-path"] / "safer-c2rust" / "lifetime-resolver"
    exec_cmd(f"{lifetime_resolver} -f --merge-field-lifetimes {output / 'lib.rs'} -L {output / 'target' / 'debug' / 'deps'}", 
            output, dismiss_error=True, timeout=7200)
    
    validate_res = validate_project_compilability(output)
    if validate_res["success"]:
        logger.success(f"resolve lifetime success! result: {output}")
        return
    
    if not rollback:
        logger.error(f"resolve lifetime failed! result: {output}")
        exit(1)
        
    logger.info(f"resolve lifetime failed, Roll back to before optimization!")
    shutil.rmtree(output)
    shutil.copytree(input, output)
        
    
def fix_unsafe(input: Path, rollback=False):
    output = input.parent / "P4_result"
    pre_script = BASE / "scripts" / "pre_unsafe_fix.py"
    
    shutil.rmtree(output, ignore_errors=True)
    shutil.copytree(input, output)
        
    logger.info(f"Start fix unsafe for {input} ...")
    logger.info(f"run the pre-process script({pre_script}) ...")
    exec_cmd(f"python3 {pre_script} {output}", output)
    
    logger.info(f"Start fix unsafe ...")
    unsafe_fixer = BASE / CONFIG["project"]["target-path"] / "safer-c2rust" / "unsafe-fixer"
    exec_cmd(f"{unsafe_fixer} {output}", output)
    
    validate_res = validate_project_compilability(output)
    if validate_res["success"]:
        logger.success(f"fix unsafe success! result: {output}")
        return
    
    fix_unsafe_error(output, validate_res["build_errors"])
    
    validate_res = validate_project_compilability(output)
    if validate_res["success"]:
        logger.success(f"fix unsafe success! result: {output}")
        return
    
    if not rollback:
        logger.error(f"fix unsafe failed! result: {output}")
        exit(1)
    
    logger.info(f"fix unsafe failed, Roll back to before optimization!")
    shutil.rmtree(output)
    shutil.copytree(input, output)


def parse_safe_analysis_result(result: Path):
    logger.info(f"Start analysis the safety performance of : ({result}) ...")
    safe_analyzer = BASE / CONFIG["project"]["target-path"] / "safe-analyzer" / "safe-analyzer"
    
    # analysis the type define
    logger.info(f"Start analysis the type define of : ({result}) ...")
    type_define = exec_cmd(f"{safe_analyzer} --count-type-define {result}", result.parent)
    type_define = type_define.splitlines()
    total_title, total_number = type_define[0].split(":")
    type_define_res = {total_title.strip(): total_number.strip()}
    type_define_details = []
    
    for line in type_define[2:]:
        _name, _type, _count = line.split(",")
        type_define_details.append({"name": _name.strip(), "type": _type.strip(), "count": _count.strip()})
    
    type_define_res["details"] = type_define_details
    
    # analysis the unsafe block/function and the raw pointers
    logger.info(f"Start analysis the unsafe block/function and the raw pointers of : ({result}) ...")
    unsafe = exec_cmd(f"{safe_analyzer} {result}", result.parent).splitlines()
    unsafe_res = {}
    for line in unsafe:
        name, value = line.split(":")
        unsafe_res[name.strip()] = int(value.strip())
    
    deref_rp = exec_cmd(f"{safe_analyzer} --count-deref-rp {result}", result.parent).splitlines()
    deref_rp_title, deref_rp_number = deref_rp[0].split(":")
    unsafe_res[deref_rp_title.strip()] = int(deref_rp_number.strip())
    logger.success(f"Analysis the unsafe block/function and the raw pointers of {result} success!")
    
    return {"type define result": type_define_res, "unsafe result": unsafe_res}
    

@click.group(chain=True)
@click.option("--work_dir", "-w", type=click.Path(exists=False, file_okay=False, writable=True, path_type=Path, resolve_path=True),
              default=RESULT, help="The work directory", show_default=f"{RESULT}/<project-name>_<datetime>")
@click.pass_context
def cli(ctx, work_dir: Path):
    ctx.ensure_object(dict)
    ctx.obj["work_dir"] = work_dir
    work_dir.mkdir(parents=True, exist_ok=True)


@cli.command()
@click.option("--src", "-s", type=click.Choice(["local", "osc"], case_sensitive=False), default="local", show_default=True,
              help="""Choose the source of the c project, 
                    if you want to translate the local c project, you should specify the `--local` option; 
                    if you want to translate the c project from osc, you should specify the `--project_name` and `--osc_branch` option.""")
@click.option("--local_path", type=click.Path(exists=True, file_okay=False, path_type=Path, resolve_path=True),
              help="The local path of the c project, if the src is `local`, you should specify this option")
@click.option("--project_name", type=str, help="The project name, if the src is `orc`, you should specify this option")
@click.option("--osc_branch", type=str, default=CONFIG["osc"]["default-branch"], show_default=True, 
              help="The osc distribution, if the src is `osc`, you should specify this option")
@click.option("--mode", type=click.Choice(["auto","script"], case_sensitive=False), default="auto", show_default=True,
              help="""Choose the mode to do the original c2rsut translate,
                    if use auto mode, you need to specify the compile_commands.json generate method by `--gencc`; 
                    if use script mode, you need to specify the script path by `--script`.""")
@click.option("--gencc", type=click.Choice(["makefile", "cmake"], case_sensitive=False), default="makefile", show_default=True,
              help="""Choose the method to generate compile_commands.json, if use script, you should set the `--mode` to AUTO.""")
@click.option("--script", type=click.Path(exists=True, dir_okay=False, path_type=Path, resolve_path=True), show_default=True,
              help="""The shell or python script to do the c2rust translation, you should set the `--mode` to SCRIPT, 
                  metion that the script should take two arguments, the first is the c project path, the second is the output path.""")
@click.pass_context
def c2rust(ctx, src: str, local_path: Path, project_name: str, osc_branch: str, mode: str, gencc: str, script: Path):
    work_dir = ctx.obj["work_dir"]
    
    if src == "local":
        project_name = local_path.stem
        
    # if output is project default result folder, create a sub-folder automatically
    if work_dir == RESULT:
        work_dir = work_dir / f"{project_name}_{datetime.now().strftime('%y%m%d_%H%M%S')}"
        ctx.obj["work_dir"] = work_dir
    
    if work_dir.exists():
        shutil.rmtree(work_dir)
    logger.info(f"Crate project work directory: {work_dir}")
    work_dir.mkdir(parents=True)
    
    logger.add(work_dir / "debug.log", format="{time:YYYY-MM-DD HH:mm:ss} {level} {message}", 
               backtrace=True, diagnose=True, level="DEBUG")
        
    c_project = work_dir / "P0_original"
    
    if src == "local":
        logger.info(f"Copy the original c project to work directory as {c_project} ...")
        shutil.copytree(local_path, c_project)
        logger.success(f"Copy the C project to work directory success!")
    else:
        logger.info(f"Clone the original c project from osc to work directory as {c_project} ...")
        spec_dir = work_dir / f"{project_name}_{osc_branch}"
        url = CONFIG['osc']['openEuler'] + project_name
        exec_cmd(f"git clone --depth=1 -b {osc_branch} {url} {spec_dir}", work_dir)
        logger.success(f"Clone the {project_name} from osc success!")
        
        logger.info(f"Start build the original C prjoect({project_name}) by rpmbuild ...")
        # build_dir = work_dir / "_c-build"
        # build_dir.mkdir(exist_ok=True)
        exec_cmd(f'rpmbuild --define "_sourcedir {spec_dir}"  --define "_topdir {c_project}" -bc --nocheck {project_name}.spec', spec_dir)
        logger.success(f"Build the original C prjoect({project_name}) by rpmbuild success!")
        
        for folder in (c_project / "BUILD").iterdir():
            if folder.is_dir() and folder.name.startswith(project_name):
                c_dir_builded =  folder
                break
        else:
            logger.error(f"Can't find the builded C project in {c_project / 'BUILD'}")
            sys.exit(1)

        if project_name in CONFIG["osc-project-build-folder"]:
            c_dir_builded = c_dir_builded / CONFIG["osc-project-build-folder"][project_name]
        
        c_project = c_dir_builded
        logger.success(f"Get project({project_name}) for osc({url}) success! The project is in {c_project}")
    
    
    after_translate = work_dir / "P1_after_c2rust"
    after_translate.mkdir(parents=True, exist_ok=True)
    
    if mode == "script":
        if script is None:
            logger.error("You should specify the script path by `--script`")
            sys.exit(1)
        
        logger.info("Start the original c2rsut translate by SCRIPT mode ...")
        if script.suffix == ".py":
            exec_cmd(f"python3 {script} {c_project} {after_translate}", work_dir)
        elif script.suffix == ".sh":
            exec_cmd(f"{script} {c_project} {after_translate}", work_dir)
        else:
            logger.error("The script should be a python or shell script!")
            sys.exit(1)
    else:
        logger.info("Start the original c2rsut translation by AUTO mode ...")
        logger.info(f"Generate compile_commands.json by {mode} ...")
        if gencc == "cmake":
            cmake_cache = c_project / "CMakeCache.txt"
            if cmake_cache.exists():
                cmake_cache.unlink()
            exec_cmd("cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON", c_project)
        else:
            exec_cmd("make clean", c_project, dismiss_error=True)
            exec_cmd("intercept-build make", c_project)
            
        compile_commands = c_project / "compile_commands.json"
        
        logger.info(f"Fix the compile_commands.json ...")
        fix_oe_gcc_args(compile_commands)
        logger.success(f"Generate {compile_commands}(size: {compile_commands.stat().st_size}) success!")
        
        c2rust = BASE / "bin" / "c2rust" / "c2rust"
        
        logger.info("Start the original c2rsut translate ...")
        exec_cmd(f"{c2rust} transpile {compile_commands} -e -o {after_translate}", c_project)
          
    # fix_type_errors(after_translate)
    # fix_dup_symbol_errors(after_translate)
    
    validate_res = validate_project_compilability(after_translate)
    if not validate_res["success"]:
        logger.error(f"Translate by original c2rsut failed! The result is in {after_translate}")
        exit(1)
        
    logger.success(f"Translate by original c2rsut success! The result is in {after_translate}")
    

@cli.command()
@click.option("--project", type=click.Path(exists=True, file_okay=False, path_type=Path, resolve_path=True),
              help="The project path of the result after original translation, set it if you want to `safer` tools without `c2rust` sub-command")
@click.option("--is_resolve_imports", "-im", type=bool, default=True, help="Turn the imports resolver on", show_default=True)
@click.option("--is_resolve_lifetime", "-lt", type=bool, default=True, help="Turn the lifetime resolver on", show_default=True)
@click.option("--is_fix_unsafe", "-us", type=bool, default=True, help="Turn the unsafe fixer on")
@click.pass_context
def safer(ctx, project, is_resolve_imports, is_resolve_lifetime, is_fix_unsafe):
    work_dir = ctx.obj["work_dir"].resolve()
    
    if project:
        if work_dir == RESULT:
            project_name = project.stem
            work_dir = work_dir / f"{project_name}_{datetime.now().strftime('%y%m%d_%H%M%S')}"
            ctx.obj["work_dir"] = work_dir
            
        after_c2rust = work_dir / "P1_after_c2rust"
        
        if not after_c2rust.exists():
            shutil.copytree(project, after_c2rust)
    
    debug_log = work_dir / "debug.log"
    if not debug_log.exists():
        logger.add(debug_log, format="{time:YYYY-MM-DD HH:mm:ss} {level} {message}", backtrace=True, diagnose=True, level="DEBUG")
    
    logger.info(f"Start the safer-c2rust processes ...")
    if is_resolve_imports:
        if not (work_dir / "P1_after_c2rust").is_dir():
            logger.error("You should has the original c2rust result in the work directory before do the imports resolve!")
            sys.exit(1)
        resolve_imports(work_dir / "P1_after_c2rust", rollback=False)
    else:
        logger.info(f"Skip the imports resolve process!")
        shutil.copytree(work_dir / "P1_after_c2rust", work_dir / "P2_after_resolve_imports")
    
    if is_resolve_lifetime:
        if not (work_dir / "P2_after_resolve_imports").is_dir():
            logger.error("You should has the imports resolved result in the work directory before do the lifetime resolve!")
            sys.exit(1)
        resolve_lifetime(work_dir / "P2_after_resolve_imports", rollback=True)
    else:
        logger.info(f"Skip the lifetime resolve process!")
        shutil.copytree(work_dir / "P2_after_resolve_imports", work_dir / "P3_after_resolve_lifetime")
    
    if is_fix_unsafe:
        if not (work_dir / "P3_after_resolve_lifetime").is_dir():
            logger.error("You should has the lifetime resolved result in the work directory before do the unsafe fix!")
            sys.exit(1)
        fix_unsafe(work_dir / "P3_after_resolve_lifetime", rollback=False)
    else:
        logger.info(f"Skip the unsafe fix process!")
        shutil.copytree(work_dir / "P3_after_resolve_lifetime", work_dir / "P4_result")
    
    result = work_dir / "P4_result"
    
    exec_cmd("cargo clean", result)
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
    elif func_contains_raw_pointer_before < (after - before):
        result = "100%"
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
    cli(obj={})
