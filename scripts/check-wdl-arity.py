#!/usr/bin/env python3
"""Checks every if()/equals()/not() call in a generated Logic App template's
workflow definition for correct argument count (if: 3, equals: 2, not: 1).

Exists because both are real bugs this repo shipped once: a hand-built
nested if() with a stray trailing argument (arity 4, not 3), and a
null-vs-empty-string comparison bug that a strict equals() argument count
wouldn't have caught but is worth having this pass double as a sanity net
for anyway. Run this on any generated template after touching a hand-built
WDL expression string, in addition to validate-logic-app-json.py (which
checks action reachability, not expression syntax).

Usage: python3 scripts/check-wdl-arity.py <path-to-azuredeploy-*.json> [...]
Exits non-zero if any file has an issue.
"""
import json
import re
import sys


def top_level_args(expr):
    depth = 0
    in_str = False
    args = ['']
    for c in expr:
        if c == "'":
            in_str = not in_str
            args[-1] += c
        elif not in_str and c == '(':
            depth += 1
            args[-1] += c
        elif not in_str and c == ')':
            depth -= 1
            args[-1] += c
        elif not in_str and c == ',' and depth == 0:
            args.append('')
        else:
            args[-1] += c
    return [a.strip() for a in args]


def check_calls(s, fname, expected):
    bad = []
    for m in re.finditer(r'\b' + fname + r'\(', s):
        start = m.end() - 1
        depth = 0
        in_str = False
        for j in range(start, len(s)):
            c = s[j]
            if c == "'":
                in_str = not in_str
            elif not in_str:
                if c == '(':
                    depth += 1
                elif c == ')':
                    depth -= 1
                    if depth == 0:
                        n = len(top_level_args(s[start + 1:j]))
                        if n != expected:
                            bad.append((n, s[max(0, m.start() - 10):j + 3][:200]))
                        break
    return bad


def find_definitions(template):
    """Handles a standalone workflow definition (top-level 'actions'), a
    single-playbook ARM deployment template (definition nested under
    resources[].properties.definition), and a combined/bundle template
    (resources[].properties.template is itself a nested ARM deployment,
    recursively, one level per playbook in the bundle) -- returns every
    workflow definition found, since a bundle template has one per
    nested playbook."""
    if "actions" in template and "triggers" in template:
        return [template]
    found = []
    for res in template.get("resources", []):
        props = res.get("properties", {})
        if "definition" in props:
            found.append(props["definition"])
        if "template" in props:
            found.extend(find_definitions(props["template"]))
    if not found:
        raise ValueError("could not find any workflow definition in this file")
    return found


def check_file(path):
    template = json.loads(open(path).read())
    definitions = find_definitions(template)
    issues = []

    def walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
        elif isinstance(obj, str) and obj.startswith('@'):
            issues.extend(("if", n, snip) for n, snip in check_calls(obj, 'if', 3))
            issues.extend(("equals", n, snip) for n, snip in check_calls(obj, 'equals', 2))
            issues.extend(("not", n, snip) for n, snip in check_calls(obj, 'not', 1))

    for defn in definitions:
        walk(defn)
    return issues


def main():
    if len(sys.argv) < 2:
        print("usage: check-wdl-arity.py <file.json> [...]", file=sys.stderr)
        sys.exit(2)
    any_bad = False
    for path in sys.argv[1:]:
        issues = check_file(path)
        if issues:
            any_bad = True
            print(f"{path}: {len(issues)} issue(s)")
            for fn, n, snip in issues:
                print(f"  BAD {fn}() arity={n}: {snip}")
        else:
            print(f"{path}: OK")
    sys.exit(1 if any_bad else 0)


if __name__ == "__main__":
    main()
