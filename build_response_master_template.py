#!/usr/bin/env python3
"""Generate azuredeploy-response-all.json: one ARM deployment that deploys all
seven response (remediation) playbooks as nested deployments, exposing every
parameter each one has at the master level -- one `az deployment group
create` call instead of seven.

Same nested-deployment pattern as build_master_template.py (the six
enrichment playbooks' combined template): each playbook embedded with
expressionEvaluationOptions.scope="inner" so its own parameters()/
variables() expressions resolve against itself, not the master.

Response playbooks don't touch a Log Analytics workspace at all (no KQL,
no Azure Monitor Logs connection) -- the only thing every one of them
shares is UserAssignedManagedIdentityResourceId. Two parameter names
collide across playbooks with the same meaning and are deliberately
merged: AzureTenantId and IndicatorExpirationDays (both FileHash and
IP/URL block-indicator playbooks). Everything else keeps its own name;
PlaybookName is exposed per playbook since each Logic App needs a
distinct resource name.

SAFETY NOTE carried over unchanged from every individual response
playbook: none of the seven are wired to a Sentinel automation rule by
this template either. Combining them into one deployment doesn't change
that -- a human running the playbook manually from the incident is still
the approval gate. See README-RESPONSE.md.
"""

import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent

# (generator script, output JSON, nested-deployment name, output-prefix)
PLAYBOOKS = [
    ("build_response_account_contain.py", "azuredeploy-response-account-contain.json", "deploy-account-contain", "AccountContain"),
    ("build_response_account_disable.py", "azuredeploy-response-account-disable.json", "deploy-account-disable", "AccountDisable"),
    ("build_response_account_revoke_consent.py", "azuredeploy-response-account-revoke-consent.json", "deploy-account-revoke-consent", "AccountRevokeConsent"),
    ("build_response_device_contain.py", "azuredeploy-response-device-contain.json", "deploy-device-contain", "DeviceContain"),
    ("build_response_email_block.py", "azuredeploy-response-email-block.json", "deploy-email-block", "EmailBlock"),
    ("build_response_filehash_block.py", "azuredeploy-response-filehash-block.json", "deploy-filehash-block", "FileHashBlock"),
    ("build_response_indicator_block.py", "azuredeploy-response-indicator-block.json", "deploy-indicator-block", "IndicatorBlock"),
]

SHARED_PARAM_MAP = {
    "UserAssignedManagedIdentityResourceId": "UserAssignedManagedIdentityResourceId",
}

# Parameter names that appear in more than one playbook and are deliberately
# merged into one master parameter -- confirmed by inventory to be the only
# names, besides PlaybookName, that collide across the seven templates.
MERGE_PARAMS = {
    "AzureTenantId": {
        "type": "string", "defaultValue": "[subscription().tenantId]",
        "metadata": {"description": "Shared by the FileHash and IP/URL block-indicator playbooks. Azure AD tenant ID, required by the tiIndicators API. Defaults to the deploying subscription's tenant."},
    },
    "IndicatorExpirationDays": {
        "type": "int", "defaultValue": 180, "minValue": 1, "maxValue": 365,
        "metadata": {"description": "Shared by the FileHash and IP/URL block-indicator playbooks. How many days out from submission each block indicator expires."},
    },
}


def regenerate_all():
    for script, _, _, _ in PLAYBOOKS:
        print(f"==> Regenerating {script} ...")
        subprocess.run([sys.executable, str(HERE / script)], check=True, cwd=HERE)


def load(output_json):
    return json.loads((HERE / output_json).read_text(encoding="utf-8"))


regenerate_all()

master_params = {
    "UserAssignedManagedIdentityResourceId": {
        "type": "string", "minLength": 1,
        "metadata": {"description": "Required. Full resource ID of the existing client-owned user-assigned managed identity used by all seven Logic Apps and every managed-identity connection/HTTP call."},
    },
}

resources = []
outputs = {}

for script, output_json, deployment_name, prefix in PLAYBOOKS:
    nested_template = load(output_json)
    nested_arm_params = nested_template["parameters"]

    nested_params = {
        arm_name: {"value": f"[parameters('{master_name}')]"}
        for arm_name, master_name in SHARED_PARAM_MAP.items()
    }

    for name, spec in nested_arm_params.items():
        if name in SHARED_PARAM_MAP:
            continue

        if name == "PlaybookName":
            master_name = f"{prefix}PlaybookName"
        elif name in MERGE_PARAMS:
            master_name = name
            spec = MERGE_PARAMS[name]
        else:
            master_name = name
            if master_name in master_params:
                raise SystemExit(
                    f"unexpected duplicate parameter name '{master_name}' from {prefix} "
                    "-- add it to MERGE_PARAMS (to merge) or rename it in its own "
                    "build_response_*.py (to keep it independent)"
                )

        master_params.setdefault(master_name, spec)
        nested_params[name] = {"value": f"[parameters('{master_name}')]"}

    resources.append(
        {
            "type": "Microsoft.Resources/deployments",
            "apiVersion": "2022-09-01",
            "name": deployment_name,
            "properties": {
                "mode": "Incremental",
                "expressionEvaluationOptions": {"scope": "inner"},
                "template": nested_template,
                "parameters": nested_params,
            },
        }
    )

    for out_name in nested_template.get("outputs", {}):
        outputs[f"{prefix}{out_name}"] = {
            "type": "string",
            "value": f"[reference('{deployment_name}').outputs.{out_name}.value]",
        }


template = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "metadata": {
        "title": "Deploy all seven ErgoSOC-AU response playbooks in one deployment",
        "description": (
            "Deploys all seven response (remediation) playbooks -- Account "
            "revoke+reset, Account disable+confirm-compromised, Account "
            "revoke-app-consent, Device isolate+scan+restrict, Email "
            "block+quarantine, FileHash block-indicator, and IP/URL "
            "block-indicator -- together as nested deployments, all bound "
            "to the same client-owned user-assigned managed identity. "
            "PlaybookName is exposed per playbook (e.g. "
            "AccountContainPlaybookName, DeviceContainPlaybookName, ...) "
            "since each Logic App needs a distinct name; AzureTenantId and "
            "IndicatorExpirationDays are merged into one shared parameter "
            "each, applied to both the FileHash and IP/URL block-indicator "
            "playbooks. Everything else keeps its own per-playbook name. "
            "SAFETY: none of the seven are wired to a Sentinel automation "
            "rule by this template -- an analyst manually running a "
            "playbook from the incident is still the approval gate for "
            "every one of them. See README-RESPONSE.md before deploying."
        ),
        "prerequisites": (
            "One existing user-assigned managed identity, already granted "
            "every Microsoft Graph, WindowsDefenderATP, and Azure RBAC "
            "permission listed in README-RESPONSE.md's permissions table "
            "for whichever of the seven playbooks you intend to use. A "
            "permission a given playbook lacks doesn't block the others -- "
            "each fails independently (every write call reports its own "
            "success/failure to the incident comment, nothing is assumed)."
        ),
        "postDeployment": [
            "Authorise the Microsoft Sentinel API connection for each of the seven playbooks.",
            "Grant the managed identity whichever permissions from README-RESPONSE.md's table match the playbooks you actually intend to use.",
            "Do NOT attach any of the seven to a Sentinel automation rule unless that's a deliberate, separate decision -- run them manually from an incident's Actions menu instead.",
            "The Email block playbook's AutoExecuteBlock stays off by default; turning it on additionally requires deploying azuredeploy-automation-account-response.json -- see README-RESPONSE.md.",
        ],
        "lastUpdateTime": "2026-09-04",
        "entities": ["Account", "Host", "MailMessage", "FileHash", "IP", "URL"],
        "tags": ["Response", "Account", "Device", "Email", "FileHash", "IP", "URL", "Bundle"],
        "support": {"tier": "community"},
    },
    "parameters": master_params,
    "resources": resources,
    "outputs": outputs,
}


output_path = HERE / "azuredeploy-response-all.json"
output_path.write_text(json.dumps(template, indent=2), encoding="utf-8")
print(f"wrote {output_path} ({output_path.stat().st_size} bytes)")
print(f"{len(master_params)} master parameters exposed")
