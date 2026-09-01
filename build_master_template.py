#!/usr/bin/env python3
"""Generate azuredeploy-all.json: one ARM deployment that deploys all six enrichment
playbooks (IP, device, URL, file hash, email, account) as nested deployments, exposing
every parameter each playbook has (beyond the four always-shared identity/workspace ones)
at the master level -- so one `az deployment group create` call can configure all six.

Each playbook keeps its own dedicated Microsoft.Sentinel/Azure Monitor Logs connections;
only parameters are consolidated. Three kinds of handling:

  1. Always shared (identical across all six): UserAssignedManagedIdentityResourceId,
     WorkspaceName, WorkspaceResourceGroup, WorkspaceSubscriptionId.
  2. PlaybookName: appears in all six but MUST stay distinct (each Logic App needs its
     own resource name), so it's exposed per playbook as e.g. IPPlaybookName,
     UrlPlaybookName, ... each still defaulting to that playbook's own original name.
  3. Merged (same name, same meaning, deliberately unified into ONE master parameter,
     applied to every playbook that has it) -- see MERGE_PARAMS below. This is a
     deliberate design choice, not automatic: EnableDefenderAdvancedHunting in
     particular defaults to False for the IP playbook standalone (it's the one that
     needs the extra Graph permission/quota most narrowly) but True for the other four
     that have it; merged here it defaults to True for all five, which DOES change the
     IP playbook's behavior versus deploying azuredeploy.json standalone. Set it to
     false at deploy time if you don't want that.

Every other parameter is unique to one playbook (verified by build-time assertion) and
is exposed under its own original name, unmodified.

This script re-runs each sibling build_*.py first (so it never embeds stale JSON), then
reads their output files and embeds them as nested/inline templates.
"""

import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent

# (generator script, output JSON, nested-deployment name, output-prefix)
PLAYBOOKS = [
    ("build_template.py", "azuredeploy.json", "deploy-ip-enrichment", "IP"),
    ("build_device_template.py", "azuredeploy-device.json", "deploy-device-enrichment", "Device"),
    ("build_url_template.py", "azuredeploy-url.json", "deploy-url-enrichment", "Url"),
    ("build_filehash_template.py", "azuredeploy-filehash.json", "deploy-filehash-enrichment", "FileHash"),
    ("build_email_template.py", "azuredeploy-email.json", "deploy-email-enrichment", "Email"),
    ("build_account_template.py", "azuredeploy-account.json", "deploy-account-enrichment", "Account"),
]

SHARED_PARAM_MAP = {
    "UserAssignedManagedIdentityResourceId": "UserAssignedManagedIdentityResourceId",
    "WorkspaceName": "WorkspaceName",
    "WorkspaceResourceGroup": "WorkspaceResourceGroup",
    "WorkspaceSubscriptionId": "WorkspaceSubscriptionId",
}

# Parameter names that appear in more than one playbook and are deliberately merged into
# one master parameter (rather than kept per-playbook) -- confirmed by inventory to be
# the only names, besides PlaybookName, that collide across the six templates.
MERGE_PARAMS = {
    "LookbackDays": {
        "type": "int", "defaultValue": 14, "minValue": 1, "maxValue": 90,
        "metadata": {"description": "Shared by every playbook that has it. How far back to query Sentinel workspace tables."},
    },
    "DefenderLookbackDays": {
        "type": "int", "defaultValue": 14, "minValue": 1, "maxValue": 30,
        "metadata": {"description": "Shared by every playbook that has it (IP, Device, URL, FileHash, Email). Defender XDR Advanced Hunting lookback; raw hunting data is limited to a maximum of 30 days."},
    },
    "EnableDefenderAdvancedHunting": {
        "type": "bool", "defaultValue": True,
        "metadata": {"description": "Shared by every playbook that has it (IP, Device, URL, FileHash, Email). Query Defender XDR Advanced Hunting through Microsoft Graph; requires ThreatHunting.Read.All. Defaults to true here -- note this turns it ON for the IP playbook too, which defaults it OFF when deployed standalone as azuredeploy.json. Set to false at deploy time to keep IP's original off-by-default behavior (that also turns it off for the other four)."},
    },
    "EnableMicrosoftThreatIntelligence": {
        "type": "bool", "defaultValue": True,
        "metadata": {"description": "Shared by the URL and Email playbooks. Query Microsoft Threat Intelligence (MDTI) host/domain reputation through Microsoft Graph; requires ThreatIntelligence.Read.All."},
    },
    "VirusTotalApiKey": {
        "type": "securestring", "defaultValue": "",
        "metadata": {"description": "Shared by the IP and URL playbooks (same VirusTotal account, different endpoints). Leave blank to skip. The free public API forbids business-workflow use, so supply a Premium key."},
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
        "metadata": {"description": "Required. Full resource ID of the existing client-owned user-assigned managed identity used by all six Logic Apps and every managed-identity connection."},
    },
    "WorkspaceName": {
        "type": "string", "metadata": {"description": "Log Analytics / Sentinel workspace name."},
    },
    "WorkspaceResourceGroup": {
        "type": "string", "defaultValue": "[resourceGroup().name]",
        "metadata": {"description": "Resource group of the Sentinel workspace."},
    },
    "WorkspaceSubscriptionId": {
        "type": "string", "defaultValue": "[subscription().subscriptionId]",
        "metadata": {"description": "Subscription of the Sentinel workspace."},
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
                    "build_*.py (to keep it independent)"
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
        "title": "Deploy all six Sentinel enrichment playbooks in one deployment",
        "description": (
            "Deploys the IP, device, URL, file hash, reported-email, and account (user) "
            "enrichment playbooks together as nested deployments, all bound to the same "
            "client-owned user-assigned managed identity and the same Sentinel workspace. "
            "Every parameter each playbook has is exposed here: parameters unique to one "
            "playbook keep their own name; PlaybookName is exposed per playbook (e.g. "
            "IPPlaybookName, UrlPlaybookName, ...) since each Logic App needs a distinct "
            "name; a handful of same-name, same-meaning parameters (LookbackDays, "
            "DefenderLookbackDays, EnableDefenderAdvancedHunting, "
            "EnableMicrosoftThreatIntelligence, VirusTotalApiKey) are deliberately merged "
            "into one shared master parameter applied to every playbook that has it -- "
            "see EnableDefenderAdvancedHunting's own description for the one behavior "
            "change this causes (it turns Defender Advanced Hunting on by default for "
            "the IP playbook too, which defaults it off when deployed standalone). "
            "Each playbook keeps its own dedicated Microsoft Sentinel and Azure Monitor "
            "Logs connections. Deploy this once instead of the six azuredeploy-*.json "
            "files separately; each individual template still deploys and updates "
            "independently afterward if you want to change just one playbook."
        ),
        "prerequisites": (
            "A Microsoft Sentinel-enabled Log Analytics workspace and one existing "
            "user-assigned managed identity, already granted every RBAC role and "
            "Microsoft Graph application permission listed across README.md, "
            "README-DEVICE.md, README-URL.md, README-FILEHASH.md, README-EMAIL.md, and "
            "README-ACCOUNT.md. A permission a given playbook lacks doesn't block the "
            "others -- each source inside each playbook fails open independently."
        ),
        "postDeployment": [
            "Confirm all twelve API connections (two per playbook) show the selected managed identity.",
            "Attach whichever of the six playbooks you want to a Sentinel incident automation rule.",
            "Review EnableDefenderAdvancedHunting's default (true here, false for the IP playbook "
            "standalone) and set it explicitly if you don't want that change.",
        ],
        "lastUpdateTime": "2026-09-01",
        "entities": ["IP", "Host", "Url", "FileHash", "MailMessage", "Account"],
        "tags": ["Enrichment", "IP", "Device", "URL", "FileHash", "Email", "Account", "Bundle"],
        "support": {"tier": "community"},
    },
    "parameters": master_params,
    "resources": resources,
    "outputs": outputs,
}


output_path = HERE / "azuredeploy-all.json"
output_path.write_text(json.dumps(template, indent=2), encoding="utf-8")
print(f"wrote {output_path} ({output_path.stat().st_size} bytes)")
print(f"{len(master_params)} master parameters exposed")
