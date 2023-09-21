import re
from pathlib import Path
from typing import Dict

import click


# let ref mut <variable> = <value>; to let <variable> = &mut (<value>); 
# let ref <variable> = <value>; to let <variable> = &(<value>);
PATTERNS  = {
    r"let\s+ref\s+mut\s+(\w+)\s*=\s*([\s\S]*?);" : r"let \1 = &mut (\2);",
    r"let\s+ref\s+(\w+)\s*=\s*(.*);"             : r"let \1 = &(\2);"
    }


def text_replace_by_pattern(target: Path, search_pattern: str, replace_pattern: str):
    with target.open("r") as f:
        content = f.read()
    
    content = re.sub(search_pattern, replace_pattern, content)

    with target.open("w") as f:
        f.write(content)


def fix_ref(target: Path, patterns: Dict):    
    files = list(target.glob("**/*.rs"))
    for file in files:
        for search_pattern, replace_pattern in patterns.items():    
            text_replace_by_pattern(file, search_pattern, replace_pattern)
    

@click.command()
@click.argument("execute_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def cli(execute_path: Path):
    fix_ref(execute_path, PATTERNS)


if __name__ == "__main__":
    cli()
