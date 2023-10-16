#!/usr/bin/python3

import sys
import shutil 
from datetime import datetime
from pathlib import Path

import click
from loguru import logger

from scripts.utils import exec_cmd, get_configs


logger.remove()
BASE = Path(__file__).parent.resolve()
CONF = get_configs(BASE / "config.toml")
BIN =  Path(BASE / CONF["project"]["target-path"])
BUILD_ENV = {"RUSTFLAGS": "-Awarnings"}


def setup_logger():
    """_summary_
    Setup logger for build.py
    """
    log_folder = Path(BASE / "logs")
    log_folder.mkdir(exist_ok=True)
    
    logger.remove()
    logger.add(log_folder / f"build_{datetime.now().strftime('%y%m%d_%H%M%S')}.log", format="{time:YYYY-MM-DD HH:mm:ss} {level} {message}",
               level="DEBUG",backtrace=True, diagnose=True)
    logger.add(sys.stdout, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level} {message}</level>",  
               level="INFO", colorize=True )


def set_rust():
    rust_version = CONF["rust"]["version"]
    
    logger.info(f"check rust version ...")
    output = exec_cmd(f"rustup toolchain list", BASE)
    versions = output.split("\n")
    
    if not any([version.startswith(rust_version) for version in versions]):
        logger.info(f"Install rust version {rust_version} ...")
        exec_cmd(f"rustup toolchain install {rust_version}", BASE)
        logger.success(f"Install rust version {rust_version} success!")
    
    logger.info(f"Set default rust to {rust_version} ...")
    exec_cmd(f"rustup override set {rust_version}", BASE)
    logger.success(f"Set default rust to {rust_version} success!")
    
    logger.info(f"Add rust component: rustc-dev ...")
    exec_cmd(f"rustup component add rustc-dev", BASE)
    logger.success(f"Add rust component: rustc-dev success!")

    
def build_orginal_c2rust():    
    version = CONF['c2rust']['version']
    repo = CONF['c2rust']['repo']
    
    if (BASE / "C2Rust").exists():
        logger.info(f"Delete C2Rust folder ...")
        shutil.rmtree(BASE / "C2Rust")
        
    logger.info(f"Download original C2Rust ...")
    exec_cmd(f"git clone --depth=1 --branch {version} {repo}", BASE)
    logger.success(f"Download original C2Rust success!")
    
    logger.info(f"Build original C2Rust ...")
    exec_cmd(f"cargo clean", path=BASE / "C2Rust")
    exec_cmd(f"cargo build --release", path=BASE / "C2Rust", env=BUILD_ENV)
    
    logger.info(f"Copy binaries ...")
    c2rust_bin_path = BIN / "c2rust"
    if c2rust_bin_path.exists():
        shutil.rmtree(c2rust_bin_path)
    Path(BASE / "C2Rust" / "target" / "release").rename(c2rust_bin_path)
    
    logger.success(f"Build original C2Rust success!")
    

def build_safer_c2rust():
    logger.info(f"Build import resolver ...")
    exec_cmd(f"cargo clean", BASE)
    exec_cmd(f"cargo build --release --bin import-resolver", path=BASE, env=BUILD_ENV)
    logger.success(f"Build import resolver success!")
    
    logger.info(f"Build lifetime resolver ...")
    exec_cmd(f"cargo build --release --bin lifetime-resolver", path=BASE, env=BUILD_ENV)
    logger.success(f"Build lifetime resolver success!")
    
    logger.info(f"Build unsafe fixer ...")
    exec_cmd(f"cargo build --release --bin unsafe-fixer", path=BASE, env=BUILD_ENV)
    logger.success(f"Build unsafe fixer success!")

    logger.info(f"Copy binaries ...")
    safer_bin_path = BIN / "safer-c2rust"
    if safer_bin_path.exists():
        shutil.rmtree(safer_bin_path)
    Path(BASE / "target" / "release").rename(safer_bin_path)
    
    logger.success(f"Build safer-c2rust success!")


def build_analysis_tool():
    logger.info(f"Build analysis tool ...")
    exec_cmd(f"cargo clean", path=BASE / "safe-analyzer")
    exec_cmd(f"cargo build --release", path=BASE / "safe-analyzer", env=BUILD_ENV)
    
    logger.info(f"Copy binaries ...")
    analyzer_bin_path = BIN / "safe-analyzer"
    if analyzer_bin_path.exists():
        shutil.rmtree(analyzer_bin_path)
    Path(BASE / "safe-analyzer" / "target" / "release").rename(analyzer_bin_path)
    
    logger.success(f"Build analysis tool success!")


@click.command()
@click.option("--all", "-a", is_flag=True, default=False, help="Build all")
@click.option("--c2rust", is_flag=True, default=False, help="Build c2rust")
@click.option("--safer", is_flag=True, default=False, help="Build safer-c2rust")
@click.option("--analyzer", is_flag=True, default=False, help="Build analyzer")
def cli(all, c2rust, safer, analyzer):
    if not any([all, c2rust, safer, analyzer]):
        logger.error(f"Please specify build target!")
        sys.exit(1)
    
    set_rust()

    if all:
        c2rust = True
        safer = True
        analyzer = True
    
    BIN.mkdir(exist_ok=True)
    if c2rust:
        build_orginal_c2rust()
    
    if safer:
        build_safer_c2rust()
    
    if analyzer:
        build_analysis_tool()
    


if __name__ == "__main__":
    setup_logger()
    cli()
