"""Normalize/augment docstrings across the codebase.

This script parses Python files, finds functions and methods missing
complete docstring sections (Args, Returns, Raises, Example) and adds
intelligent defaults based on function signatures.

Caveats: This is a best-effort tool; review diffs for correctness.
"""

from __future__ import annotations

import ast
import os
import sys
from typing import List

TARGET_DIRS = [
    "specter/core",
    "specter/scanners",
    "specter/models",
    "specter/reporting",
    "specter/utils",
    "specter/correlation",
    "examples",
    "tests",
]

PY_FILES: List[str] = []
for base in TARGET_DIRS:
    if not os.path.isdir(base):
        continue
    for root, dirs, files in os.walk(base):
        for f in files:
            if f.endswith(".py"):
                PY_FILES.append(os.path.join(root, f))
# also include top-level main.py
if os.path.exists("main.py"):
    PY_FILES.append("main.py")

SECTION_KEYS = ["Args:", "Returns:", "Raises:", "Example:"]


def needs_sections(doc: str) -> List[str]:
    missing = []
    if doc is None:
        return SECTION_KEYS.copy()
    for k in SECTION_KEYS:
        if k not in doc:
            missing.append(k)
    return missing


def build_docstring(func_name: str, args: List[str], returns: bool, existing: str | None) -> str:
    brief = existing.splitlines()[0] if existing else f"{func_name} function."
    parts = [brief, "", "Args:"]
    if args:
        for a in args:
            parts.append(f"    {a} (Any): Description of {a}.")
    else:
        parts.append("    None")
    if returns:
        parts.append("")
        parts.append("Returns:")
        parts.append("    Any: Description of return value.")
    parts.append("")
    parts.append("Raises:")
    parts.append("    Exception: On unexpected errors.")
    parts.append("")
    parts.append("Example:")
    parts.append(f"    >>> # Example usage of {func_name}\n    >>> pass")
    return "\n".join(parts)


def process_file(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception:
        return False
    try:
        tree = ast.parse(src)
    except Exception:
        return False
    modified = False

    class DocUpdater(ast.NodeTransformer):
        def visit_FunctionDef(self, node: ast.FunctionDef):
            return self._maybe_update(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
            return self._maybe_update(node)

        def visit_ClassDef(self, node: ast.ClassDef):
            # update methods inside class
            self.generic_visit(node)
            return node

        def _maybe_update(self, node):
            nonlocal modified
            name = node.name
            existing = ast.get_docstring(node)
            missing = needs_sections(existing)
            if missing:
                # collect arg names (skip self/cls)
                args = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
                returns = node.returns is not None
                new_doc = build_docstring(name, args, returns, existing)
                # create new Expr node with Constant string
                doc_node = ast.Expr(value=ast.Constant(value=new_doc))
                if existing:
                    # replace first statement
                    if isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                        node.body[0] = doc_node
                    else:
                        node.body.insert(0, doc_node)
                else:
                    node.body.insert(0, doc_node)
                modified = True
            return node

    updater = DocUpdater()
    new_tree = updater.visit(tree)
    if modified:
        ast.fix_missing_locations(new_tree)
        try:
            new_src = ast.unparse(new_tree)
        except Exception:
            return False
        # write backup
        try:
            with open(path + ".bak", "w", encoding="utf-8") as f:
                f.write(src)
            with open(path, "w", encoding="utf-8") as f:
                f.write(new_src)
            print(f"Updated docstrings in: {path}")
            return True
        except Exception as e:
            print(f"Failed to write {path}: {e}")
            return False
    return False


if __name__ == "__main__":
    updated = 0
    for p in PY_FILES:
        ok = process_file(p)
        if ok:
            updated += 1
    print(f"Docstring normalization complete. Files updated: {updated}")
    if updated > 0:
        print("Backups saved with .bak suffix")
