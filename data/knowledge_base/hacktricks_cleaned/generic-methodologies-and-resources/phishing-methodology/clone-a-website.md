---
source_name: HackTricks
source_url: https://book.hacktricks.xyz/generic-methodologies-and-resources/phishing-methodology/clone-a-website
source_date: '2024-01-15'
cve_tags: []
chunk_id: ''
---

# Cloning a Website

{{#include ../../banners/hacktricks-training.md}}

For a phishing assessment sometimes it might be useful to completely **clone/dump a website**.

Note that you can add also some payloads to the cloned website like a BeEF hook to "control" the tab of the user.

There are different tools you can use for this purpose:

## wget

```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```

## goclone

```bash
#https://github.com/imthaghost/goclone
goclone <url>
```

## Social Engineering Toolit

```bash
#https://github.com/trustedsec/social-engineer-toolkit
```

{{#include ../../banners/hacktricks-training.md}}