---
source_name: HackTricks
source_url: https://book.hacktricks.xyz/windows-hardening/lateral-movement/scmexec
source_date: '2024-01-15'
cve_tags: []
chunk_id: ''
---

# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** is a technique to execute commands on remote systems using the Service Control Manager (SCM) to create a service that runs the command. This method can bypass some security controls, such as User Account Control (UAC) and Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}