import ast
import pathlib
import re


def migrate_file(path: pathlib.Path) -> int:
    """Migrate test file to use auth_headers fixture via AST."""
    src = path.read_text(encoding="utf-8")

    # Drop the local _login + _auth_headers helpers (text-level regex first).
    helper_pat = re.compile(
        r"def _login\([^)]*\):\n(?:    .*\n)+?"
        r"def _auth_headers\([^)]*\):\n    return \{[^}]*\}\n\n",
        re.DOTALL,
    )
    new_src, _ = helper_pat.subn("", src)

    # Drop the local passwords dict (if still present).
    pwd_pat = re.compile(
        r"    passwords = \{[^\n]*\n(?:        \"[^\"]+\": \"[^\"]+\",?\n)+\s*\}\n\n", re.MULTILINE
    )
    new_src, _ = pwd_pat.subn("", new_src)

    # Replace _auth_headers("...") call sites with auth_headers("...")
    new_src = new_src.replace('_auth_headers("', 'auth_headers("')

    # AST walk: for every function whose body references auth_headers(...)
    # but whose arg list doesn't already contain auth_headers, inject it.
    try:
        tree = ast.parse(new_src)
    except SyntaxError as exc:
        print(f"  SyntaxError in {path.name}: {exc}")
        return 0

    # Collect all function definitions and the ranges they cover.
    insertions = []  # list of (line_no_of_args_end, indent, prefix_to_insert)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Skip if name starts with _ (helper) or is a class method other than test.
        if not node.name.startswith("test_"):
            continue
        # Already has auth_headers in args?
        has_fixt = any(a.arg == "auth_headers" for a in node.args.args)
        if has_fixt:
            continue
        # Does the body reference auth_headers("...")?
        src_repr = ast.get_source_segment(new_src, node) or ""
        if 'auth_headers("' not in src_repr:
            continue
        # Find args end (col_offset of the closing paren).
        # args.args may be empty, in which case we use defaults.
        if node.args.args:
            last = node.args.args[-1]
            arg_end_col = last.end_col
        else:
            # No args; insert "auth_headers" before the closing paren of ().
            # Find the def line; the open paren position.
            # args are empty -> the closing paren is right after "(".
            line_start = node.lineno
            # We need to find the open paren on that line.
            def_line_end_col = node.col_offset + len(
                "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            )
            # Search for '(' starting at def_line_end_col.
            line_text = new_src.split(chr(10))[line_start - 1]
            open_paren = line_text.find("(", node.col_offset)
            close_paren_col = open_paren + 1
            # Use insert-before-close-paren.
            insertions.append((line_start, close_paren_col, "auth_headers"))
            continue
        # Compute the line/col to insert after.
        if last.lineno == node.lineno:
            # Same line -- insert ", auth_headers" right after arg_end_col.
            insertions.append((last.lineno, arg_end_col, ", auth_headers"))
        else:
            # Multi-line signature -- insert on a new indented line.
            indent_match = re.match(r"^(\s*)", new_src.split(chr(10))[node.lineno - 1])
            indent = indent_match.group(1) if indent_match else ""
            # Append ", auth_headers" at end of the args list. Use a sentinel
            # so we can find the closing paren and inject right before it.
            insertions.append((last.lineno, last.end_col, ", auth_headers"))

    # Apply insertions from the bottom up so col offsets stay valid.
    # Group by line and process each line in reverse column order.
    by_line = {}
    for lineno, col, txt in insertions:
        by_line.setdefault(lineno, []).append((col, txt))
    changes = 0
    for lineno, items in by_line.items():
        items.sort(reverse=True)
        line_idx = lineno - 1
        lines = new_src.split(chr(10))
        original = lines[line_idx]
        for col, txt in items:
            original = original[:col] + txt + original[col:]
            changes += 1
        lines[line_idx] = original
        new_src = chr(10).join(lines)

    if changes > 0 or new_src != src:
        path.write_text(new_src, encoding="utf-8")
    return changes


if __name__ == "__main__":
    base = pathlib.Path("tests/unit/api")
    targets = [
        "test_users_api.py",
        "test_vulnscan_api.py",
        "test_operations_api.py",
        "test_agents_api.py",
        "test_chat_persistence.py",
    ]
    for name in targets:
        path = base / name
        if not path.exists():
            print(f"{name}: SKIP")
            continue
        try:
            n = migrate_file(path)
            print(f"{name}: {n} functions updated")
        except Exception as exc:
            print(f"{name}: ERROR {exc}")
