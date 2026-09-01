#!/usr/bin/env python3
"""Generate azuredeploy-all.json: one ARM deployment that deploys all six enrichment
playbooks (IP, device, URL, file hash, email, account) as nested deployments.

Each playbook keeps its own dedicated Microsoft.Sentinel/Azure Monitor Logs connections
and its own full set of toggle parameters (all still default to their normal, sensible
values) -- this template only threads through the handful of parameters every playbook
shares (the UAMI, the workspace) plus the two optional third-party API keys the URL
playbook accepts, so one `az deployment group create` call stands up all six instead of
six separate ones. To customize an individual playbook's other parameters (lookback
windows, per-source enable flags, watchlist alias names, etc.), either edit that nested
deployment's "parameters" block below before deploying, or redeploy that playbook's own
azuredeploy-*.json afterward with the parameters you want -- it targets the same
resource names, so it updates in place rather than creating a duplicate.

This script re-runs each sibling build_*.py first (so it never embeds stale JSON), then
reads their output files and embeds them as nested/inline templates.
"""

import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent

# (generator script, output JSON, nested-deployment name, output-prefix, needs the two
#  optional URL-only API keys threaded through)
PLAYBOOKS = [
    ("build_template.py", "azuredeploy.json", "deploy-ip-enrichment", "IP", False),
    ("build_device_template.py", "azuredeploy-device.json", "deploy-device-enrichment", "Device", False),
    ("build_url_template.py", "azuredeploy-url.json", "deploy-url-enrichment", "Url", True),
    ("build_filehash_template.py", "azuredeploy-filehash.json", "deploy-filehash-enrichment", "FileHash", False),
    ("build_email_template.py", "azuredeploy-email.json", "deploy-email-enrichment", "Email", False),
    ("build_account_template.py", "azuredeploy-account.json", "deploy-account-enrichment", "Account", False),
]

SHARED_PARAM_MAP = {
    "UserAssignedManagedIdentityResourceId": "UserAssignedManagedIdentityResourceId",
    "WorkspaceName": "WorkspaceName",
    "WorkspaceResourceGroup": "WorkspaceResourceGroup",
    "WorkspaceSubscriptionId": "WorkspaceSubscriptionId",
}


def regenerate_all():
    for script, _, _, prefix, _ in PLAYBOOKS:
        print(f"==> Regenerating {script} ...")
        subprocess.run([sys.executable, str(HERE / script)], check=True, cwd=HERE)


def load(output_json):
    return json.loads((HERE / output_json).read_text(encoding="utf-8"))


regenerate_all()

resources = []
outputs = {}

for script, output_json, deployment_name, prefix, needs_url_keys in PLAYBOOKS:
    nested_template = load(output_json)

    nested_params = {
        arm_name: {"value": f"[parameters('{master_name}')]"}
        for arm_name, master_name in SHARED_PARAM_MAP.items()
    }
    if needs_url_keys:
        nested_params["VirusTotalApiKey"] = {"value": "[parameters('VirusTotalApiKey')]"}
        nested_params["GoogleSafeBrowsingApiKey"] = {"value": "[parameters('GoogleSafeBrowsingApiKey')]"}

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
            "Each playbook keeps its own dedicated Microsoft Sentinel and Azure Monitor "
            "Logs connections and its own full set of toggle parameters at their normal "
            "defaults; only the shared identity/workspace parameters (and the URL "
            "playbook's two optional third-party API keys) are threaded through from "
            "this template. Deploy this once instead of the six azuredeploy-*.json "
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
            "To change one playbook's own parameters (lookback windows, per-source toggles, watchlist "
            "alias names, ...), redeploy that playbook's own azuredeploy-*.json with the parameters "
            "you want -- it targets the same resource names and updates in place.",
        ],
        "lastUpdateTime": "2026-09-01",
        "entities": ["IP", "Host", "Url", "FileHash", "MailMessage", "Account"],
        "tags": ["Enrichment", "IP", "Device", "URL", "FileHash", "Email", "Account", "Bundle"],
        "support": {"tier": "community"},
    },
    "parameters": {
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
        "VirusTotalApiKey": {
            "type": "securestring", "defaultValue": "",
            "metadata": {"description": "Optional, used only by the URL playbook. Leave blank to skip. The free public API forbids business-workflow use, so supply a Premium key."},
        },
        "GoogleSafeBrowsingApiKey": {
            "type": "securestring", "defaultValue": "",
            "metadata": {"description": "Optional, used only by the URL playbook. Leave blank to skip. Free Google Cloud API key."},
        },
    },
    "resources": resources,
    "outputs": outputs,
}


output_path = HERE / "azuredeploy-all.json"
output_path.write_text(json.dumps(template, indent=2), encoding="utf-8")
print(f"wrote {output_path} ({output_path.stat().st_size} bytes)")
