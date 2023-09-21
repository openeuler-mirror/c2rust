#!/usr/bin/python3

import sys
import shutil 
from pathlib import Path

import toml
from loguru import logger
from plumbum import local


BASE = Path(__file__).parent.resolve()


def setup_logger():
    """_summary_
    Setup logger for build.py
    """
    log_folder = Path(BASE / "logs")
    log_folder.mkdir(exist_ok=True)
    
    logger.remove()
    logger.add(log_folder / "build.log", format="{time:YYYY-MM-DD HH:mm:ss} {level} {message}", 
               backtrace=True, diagnose=True, rotation="20 MB", level="DEBUG")
    logger.add(sys.stdout, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level} {message}</level>",  
               level="INFO", colorize=True )


def get_configs():
    config_file = BASE / "config.toml"
    logger.info(f"Loading config file({config_file})")
    with config_file.open("r") as f:
        config = toml.load(f)
    logger.debug(f"Config: {config}")
    return config


def execute(cmd, path=BASE):
    logger.info(f"Executing command: {cmd} ...")
    tool, args = cmd.split(" ", 1)
    with local.cwd(path):
        try:
            result = local[tool](args.split(" "))
        except Exception as e:
            logger.exception(f"Executing Command failed!" )
            sys.exit(1)
        
    return result


def set_rust():
    rust_version = config["rust"]["version"]
    
    logger.info(f"check rust version ...")
    output = execute(f"rustup toolchain list")
    versions = output.split("\n")
    
    if any([version.starswith(rust_version) for version in versions]):
        logger.success(f"Rust version {rust_version} already installed!")
    else:
        logger.info(f"Install rust version {rust_version} ...")
        execute(f"rustup toolchain install {rust_version}")
        logger.success(f"Install rust version {rust_version} success!")
    
    logger.info(f"Set default rust to {rust_version} ...")
    execute(f"rustup override set {rust_version}")
    logger.success(f"Set default rust to {rust_version} success!")
    
    logger.info(f"Add rust component: rustc-dev ...")
    execute(f"rustup component add rustc-dev")
    logger.success(f"Add rust component: rustc-dev success!")

    
def build_orginal_c2rust():    
    version = config['c2rust']['version']
    repo = config['c2rust']['repo']
    
    if (BASE / "C2Rust").exists():
        logger.info(f"Delete C2Rust folder")
        shutil.rmtree(BASE / "C2Rust")
        logger.success(f"Delete C2Rust folder success!")
        
    logger.info(f"Download original C2Rust ...")
    execute(f"git clone --depth=1 --branch {version} {repo}")
    logger.success(f"Download original C2Rust success!")
    
    logger.info(f"Build original C2Rust ...")
    execute(f"cargo clean", path=BASE / "C2Rust")
    execute(f"cargo build --release", path=BASE / "C2Rust")
    logger.success(f"Build original C2Rust success!")
    

def build_safer_c2rust():
    logger.info(f"Build import resolver ...")
    execute(f"cargo clean")
    execute(f"cargo build --release --bin import-resolver")
    logger.success(f"Build import resolver success!")
    
    logger.info(f"Build lifetime resolver ...")
    execute(f"cargo build --release --bin lifetime-resolver")
    logger.success(f"Build lifetime resolver success!")
    
    logger.info(f"Build unsafe fixer ...")
    execute(f"cargo build --release --bin unsafe-fixer")
    logger.success(f"Build unsafe fixer success!")


def build_analysis_tool():
    logger.info(f"Build analysis tool ...")
    execute(f"cargo clean", path=BASE / "safe-analyzer")
    execute(f"cargo build --release", path=BASE / "safe-analyzer")
    logger.success(f"Build analysis tool success!")


def collect_binaries():
    logger.info(f"Copy binaries ...")
    bin_folder = Path(BASE / config["project"]["target-path"])
    if bin_folder.exists():
        shutil.rmtree(bin_folder)
    bin_folder.mkdir()
    
    Path(BASE / "C2Rust" / "target" / "release").rename(bin_folder / "c2rust")
    Path(BASE / "target" / "release").rename(bin_folder / "safer-c2rust")
    Path(BASE / "safe-analyzer" / "target" / "release").rename(bin_folder / "safe-analyzer")
    logger.success(f"Copy binaries success!")
    

if __name__ == "__main__":
    setup_logger()
    logger.info(f"Build start ...")
    
    config = get_configs()
    set_rust()
    build_orginal_c2rust()
    build_safer_c2rust()
    build_analysis_tool()
    collect_binaries()
    
    logger.success(f"Build success!")
