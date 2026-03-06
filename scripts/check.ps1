$ErrorActionPreference = "Stop"
$python = Join-Path $PSScriptRoot "..\..\.venv\Scripts\python.exe"
& $python -m pytest tests/
& $python -m flake8 src --count --select=E9,F63,F7,F82 --show-source --statistics
& $python -m bandit -r src -ll -ii
