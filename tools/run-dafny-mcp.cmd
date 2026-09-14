@echo off
setlocal
set "PATH=%~dp0..\.mcp-tools\dafny\dafny;%PATH%"
"C:\Users\angel\GCAD\.mcp-tools\dafny-mcp\Scripts\python.exe" -c "import pathlib, sys; source=pathlib.Path(r'C:\Users\angel\dafny-mcp\mcp.py'); sys.path[:]=[p for p in sys.path if pathlib.Path(p or '.').resolve()!=source.parent]; scope={'__name__':'__main__', '__file__':str(source)}; exec(compile(source.read_bytes(), str(source), 'exec'), scope); scope['mcp'].run(transport='stdio')"
