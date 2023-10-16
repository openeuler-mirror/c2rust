import json
from pathlib import Path

import click
from loguru import logger

            
def fix_oe_gcc_args(compile_commands_file: Path):
    with compile_commands_file.open("r") as f:
        compile_commands = json.load(f)
    
    for compile_command in compile_commands:
        if "arguments" not in compile_command:
            break
        
        arguments = compile_command["arguments"]
        for argument in arguments:
            if argument == "-Wp,-D_FORTIFY_SOURCE=2":
                arguments.remove(argument)
                break
    
    with compile_commands_file.open("w") as f:
        json.dump(compile_commands, f, indent=4)


@click.command()
@click.argument("execute_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def cli(execute_path: Path):
    logger.info(f"Fixing compile_commands.json in {execute_path} ...")
    fix_oe_gcc_args(execute_path / "compile_commands.json")
    logger.success(f"Fixing compile_commands.json in {execute_path} successfully!")


if __name__ == "__main__":
    # setup_logger(Path("/home/csslab/sandbox"))
    cli()


    