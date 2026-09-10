#!/usr/bin/env python3
"""Stronger Logic App workflow validator: on top of runAfter-reference and
duplicate-action-name checks, verifies every outputs('X')/body('X')/
actions('X') reference inside an action's inputs is actually guaranteed to
have completed by the time that action runs -- i.e. X is reachable via a
transitive runAfter chain within the same scope, OR X is a dependency an
ancestor scope (If/Foreach/Until) already established via its own runAfter
before the current action's scope was ever entered.

This catches the exact bug class ARM's own deployment-time validator
flagged: "action X cannot reference action Y ... must be in runAfter path".
"""
import json
import re
import sys


def transitive_runafter_closure(name, actions_by_name):
    """All action names guaranteed complete before `name` starts, within the
    same actions dict (walks runAfter edges backward)."""
    seen = set()
    stack = list(actions_by_name.get(name, {}).get("runAfter", {}).keys())
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(actions_by_name.get(n, {}).get("runAfter", {}).keys())
    return seen


def referenced_action_names(inputs_obj):
    blob = json.dumps(inputs_obj)
    return set(re.findall(r"(?:outputs|body|actions)\('([^']+)'\)", blob))


def check_scope(actions, guaranteed_by_ancestors, path, errors):
    """actions: the actions dict at this scope level.
    guaranteed_by_ancestors: action names already guaranteed done before this
    scope was entered (from enclosing If/Foreach's own runAfter chain)."""
    for name, action in actions.items():
        own_closure = transitive_runafter_closure(name, actions)
        available = own_closure | guaranteed_by_ancestors | {name}
        refs = referenced_action_names(action.get("inputs", {}))
        # foreach's own iteration variable name isn't an action; ignore refs
        # to names not present anywhere as an action (those are typically
        # trigger/parameter/variable lookups misparsed, or loop var names --
        # skip names never defined as an action anywhere reachable).
        for ref in refs:
            if ref in available:
                continue
            # only flag if the ref name IS a real action somewhere in this
            # scope or a nested one (avoids false positives on coincidental
            # matches); do a cheap global check via a marker set passed in.
            errors.append(
                f"{path}: action '{name}' references '{ref}' via outputs/body/actions() "
                f"but '{ref}' is not guaranteed complete (not in its own runAfter chain "
                f"or any ancestor scope's runAfter chain)"
            )

        if action.get("type") == "If":
            new_guaranteed = guaranteed_by_ancestors | own_closure | {name}
            check_scope(action.get("actions", {}), new_guaranteed, f"{path}/{name}[if]", errors)
            check_scope(action.get("else", {}).get("actions", {}), new_guaranteed, f"{path}/{name}[else]", errors)
        elif action.get("type") in ("Foreach", "Until", "Scope"):
            new_guaranteed = guaranteed_by_ancestors | own_closure | {name}
            check_scope(action.get("actions", {}), new_guaranteed, f"{path}/{name}[loop]", errors)


def all_action_names(actions, names):
    for name, action in actions.items():
        names.add(name)
        if action.get("type") == "If":
            all_action_names(action.get("actions", {}), names)
            all_action_names(action.get("else", {}).get("actions", {}), names)
        elif action.get("type") in ("Foreach", "Until", "Scope"):
            all_action_names(action.get("actions", {}), names)


def main():
    for f in sys.argv[1:]:
        d = json.load(open(f))
        errors_total = []
        for res in d.get("resources", []):
            defs = []
            if res.get("type") == "Microsoft.Logic/workflows":
                defs.append((res["name"], res["properties"]["definition"]))
            elif res.get("type") == "Microsoft.Resources/deployments":
                inner = res["properties"]["template"]
                for ires in inner.get("resources", []):
                    if ires.get("type") == "Microsoft.Logic/workflows":
                        defs.append((f"{res['name']}/{ires['name']}", ires["properties"]["definition"]))
            for wf_name, definition in defs:
                actions = definition.get("actions", {})
                # global set of every action name anywhere, so we only flag
                # references that are real (in-scope) action names, not
                # trigger/foreach-item lookups that happen to parse oddly.
                names = set()
                all_action_names(actions, names)
                errs = []
                check_scope(actions, set(), f"{f}:{wf_name}", errs)
                # filter to only refs that are real action names elsewhere
                errs = [e for e in errs if any(f"'{n}'" in e.split("references")[1].split("via")[0] for n in names)]
                errors_total += errs
        if errors_total:
            print(f"{f}: {len(errors_total)} reachability problem(s)")
            for e in errors_total:
                print("  ", e)
        else:
            print(f"{f}: OK")


if __name__ == "__main__":
    main()
