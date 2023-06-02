import os
import re

pattern_1 = r"let\s+ref\s+mut\s+(\w+)\s*=\s*([\s\S]*?);"
pattern_2 = r"let\s+ref\s+(\w+)\s*=\s*(.*);"

def replace_pattern_1(dir_path):
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if os.path.splitext(file)[1] == '.rs':
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()
                result = re.sub(pattern_1, r"let \1 = &mut (\2);", content)
                with open(file_path, 'w') as f:
                    f.write(result)

def replace_pattern_2(dir_path):
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if os.path.splitext(file)[1] == '.rs':
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()
                result = re.sub(pattern_2, r"let \1 = &(\2);", content)
                with open(file_path, 'w') as f:
                    f.write(result)



def main():
    replace_pattern_1(work_dir)
    replace_pattern_2(work_dir)


if __name__ == "__main__":
    main()