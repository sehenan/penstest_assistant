import os
import traceback

file_path = r'data\knowledge_base\exploitdb\exploits\php\webapps\27600.txt'

print("Path:", repr(file_path))
print("Exists:", os.path.exists(file_path))
print("Is file:", os.path.isfile(file_path))

try:
    with open(file_path, 'r', encoding='utf-8') as f:
        print("Length:", len(f.read()))
except Exception as e:
    traceback.print_exc()

# Let's also glob for it to see exactly what Path returns
from pathlib import Path
for p in Path(r'data\knowledge_base\exploitdb\exploits\php\webapps').rglob('27600*'):
    print("Found via glob:", repr(str(p)))
    try:
        with open(p, 'r', encoding='utf-8') as f:
            print("Length via glob:", len(f.read()))
    except Exception as e:
        traceback.print_exc()
