# Agentic Development Rules for dnscan

## Context & Requirements
- **Project**: dnscan (Fast Async DNS Scanner)
- **Language**: Python 3.12+
- **Dependency Manager**: `uv`
- **Core Architecture**: The tool is fundamentally asynchronous. It uses `asyncio` and `aiodns` for all bulk DNS resolution tasks. Blocking code or thread pools should be avoided in favor of async loops.
- **Visuals**: The CLI interface is powered by `rich`. It uses `Console` and `Progress` for beautiful, animated output. Plain `print()` statements should be avoided in favor of `rich.console`.
- **Git**: The project tracks its dependencies via `pyproject.toml` and `uv.lock`. `.venv` is strictly ignored. 

## Command Line Interface
- `dnscan.py` accepts standard flags like `-d` (domain) but also accepts a positional argument for the wordlist size (e.g. `100`, `1000`, `uk-500`).
- The syntax to run it is `uv run ./dnscan.py -d <domain> [wordlist_size]`.

## Statistics & Info
- It brute-forces domains using various built-in text wordlists.
- Capable of Zone transfers, DNSSEC validation, MX and TXT records retrieval.
- Originally a 13-year-old script, modernized as of June 2026.
