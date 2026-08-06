# Cloudflare multi-account Dashboard SSO + Entra SCIM automation

This package automates the supported configuration for customers with multiple Cloudflare accounts and one Microsoft Entra tenant.

## Files

- `Invoke-CFEntraMultiAccountScim.ps1` — PowerShell automation.
- `cf-entra-multi-account.example.json` — customer config template.

## What it configures

- One Cloudflare Dashboard SSO connector on the primary account for the email domain.
- One Entra non-gallery Enterprise Application per Cloudflare account.
- One SCIM synchronization job per Entra app.
- Entra SCIM `BaseAddress` set to `https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/scim/v2`.
- Entra SCIM `SecretToken` set to the account-specific Cloudflare SCIM Provisioning token.
- Optional Entra group/user assignments to each account-specific Enterprise Application.

## Prerequisites

PowerShell:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

Cloudflare bootstrap token in the environment variable from `cloudflare.apiTokenEnvVar`, usually:

```powershell
$env:CLOUDFLARE_API_TOKEN = "<token>"
```

Cloudflare permissions:

- `SSO Connector Edit` on the primary account.
- Permission to create Account API tokens if `cloudflare.createScimTokens=true`.
- If tokens are supplied instead, each account token needs `Account -> SCIM Provisioning -> Edit` scoped to that account.

Microsoft Graph delegated scopes:

- `Application.ReadWrite.All`
- `AppRoleAssignment.ReadWrite.All`
- `Directory.ReadWrite.All`
- `Synchronization.ReadWrite.All`

## Usage

1. Copy the sample config and edit tenant/account/group values:

```powershell
Copy-Item .\cf-entra-multi-account.example.json .\customer.json
```

2. Dry-run:

```powershell
.\Invoke-CFEntraMultiAccountScim.ps1 -ConfigPath .\customer.json
```

3. Create/configure resources and assign listed Entra groups/users, but do not enable SSO and do not start provisioning:

```powershell
.\Invoke-CFEntraMultiAccountScim.ps1 -ConfigPath .\customer.json -Apply -AssignPrincipals
```

4. Add the printed TXT verification record for the email domain.

5. Validate the Dashboard SSO IdP in Cloudflare Zero Trust.

6. Start provisioning after checking Entra mappings:

```powershell
.\Invoke-CFEntraMultiAccountScim.ps1 -ConfigPath .\customer.json -Apply -AssignPrincipals -StartProvisioning
```

7. Enable Dashboard SSO only after verification and IdP testing succeed:

```powershell
.\Invoke-CFEntraMultiAccountScim.ps1 -ConfigPath .\customer.json -Apply -EnableDashboardSso
```

## Manual/post-run steps

- Assign Cloudflare Permission Policies to the synced User Groups in each account after SCIM sync.
- Verify Entra provisioning mapping includes the `active` attribute so deprovisioning sends `active:false` to Cloudflare.
- Avoid deprecated `CF-<accountID>-<Role Name>` SCIM virtual groups; use native Cloudflare User Groups.
- Do not name customer groups with the reserved `CF` prefix.

## Safety gates in the script

- No mutating action without `-Apply`.
- Dashboard SSO is not enabled unless `-EnableDashboardSso` is supplied.
- Provisioning is not started unless `-StartProvisioning` is supplied.
- Principal assignments are skipped unless `-AssignPrincipals` is supplied.
- SCIM token values are not written to the state file.
