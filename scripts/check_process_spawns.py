#!/usr/bin/env python3
"""Enforce the shared console policy at all Rust production spawn sites."""
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
HELPER = "crates/keyferry-core/src/process.rs"


def production_code(source: str) -> str:
    # Preserve offsets while removing literals and comments before balancing test modules.
    literals = r'r(#{0,})"[\s\S]*?"\1|"(?:\\[\s\S]|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/'
    literals += r"|'(?:\\[\s\S]|[^'\\])'"
    code = re.sub(literals, lambda m: " " * len(m[0]), source)
    for match in list(re.finditer(r'#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{', code))[::-1]:
        depth = 1
        end = match.end()
        while end < len(code) and depth:
            depth += (code[end] == "{") - (code[end] == "}")
            end += 1
        if depth:
            raise ValueError("Unbalanced test module")
        code = code[:match.start()] + " " * (end - match.start()) + code[end:]
    return code


def main() -> None:
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--", "apps", "crates", "tools"],
        cwd=ROOT, text=True).splitlines()
    failures = []
    for name in sorted(set(paths)):
        path = Path(name)
        if path.suffix != ".rs" or "tests" in path.parts or path.stem.endswith("_tests") or name == HELPER:
            continue
        code = production_code((ROOT / path).read_text(encoding="utf-8"))
        for match in re.finditer(r'\bCommand\s*::\s*new\s*\(', code):
            failures.append(f"{name}:{code[:match.start()].count(chr(10)) + 1}: raw Command constructor")
        if re.search(r'\bcreation_flags\s*\(', code):
            failures.append(f"{name}: platform spawn policy outside shared helper")
    if failures:
        raise SystemExit("\n".join(failures))
    print("process spawning: PASS (all production commands use shared policy)")


if __name__ == "__main__":
    main()
