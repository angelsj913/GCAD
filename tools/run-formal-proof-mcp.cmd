@echo off
setlocal
set "ELAN_HOME=C:\Users\angel\GCAD\.mcp-tools\elan"
set "PATH=%ELAN_HOME%\toolchains\leanprover--lean4---v4.33.1\bin;%PATH%"
"C:\Users\angel\AppData\Local\Programs\Python\Python312\python.exe" -X utf8 -m formal_proof_mcp
