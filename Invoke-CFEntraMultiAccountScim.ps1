<#
.SYNOPSIS
Automates Cloudflare Dashboard SSO plus Microsoft Entra SCIM apps for multiple Cloudflare accounts.

.DESCRIPTION
Supported topology:
- One Cloudflare Dashboard SSO connector for the email domain, on one primary Cloudflare account.
- One Microsoft Entra non-gallery Enterprise Application per Cloudflare account for SCIM.
- One Cloudflare SCIM endpoint/token per Cloudflare account.

Requires PowerShell 7+, Microsoft.Graph.Authentication, a Cloudflare bootstrap API token,
and Microsoft Graph delegated scopes: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
Directory.ReadWrite.All, Synchronization.ReadWrite.All.

Safety gates:
- No mutating action without -Apply.
- Dashboard SSO is not enabled unless -EnableDashboardSso is supplied.
- Entra provisioning is not started unless -StartProvisioning is supplied.
- Entra group/user assignments are skipped unless -AssignPrincipals is supplied.
#>
param(
  [Parameter(Mandatory = $true)][string]$ConfigPath,
  [switch]$Apply,
  [switch]$EnableDashboardSso,
  [switch]$AssignPrincipals,
  [switch]$StartProvisioning,
  [string]$StatePath = ".\cf-entra-scim-state.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GraphScopes = @(
  "Application.ReadWrite.All",
  "AppRoleAssignment.ReadWrite.All",
  "Directory.ReadWrite.All",
  "Synchronization.ReadWrite.All"
)

function Write-Step {
  param([string]$Message)
  Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Plan {
  param([string]$Message)
  Write-Host "[PLAN] $Message" -ForegroundColor Yellow
}

function Get-PropertyValue {
  param([object]$Object, [string]$Name, [object]$Default = $null)
  if ($null -eq $Object) { return $Default }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -eq $property -or $null -eq $property.Value) { return $Default }
  return $property.Value
}

function Escape-ODataString {
  param([string]$Value)
  return $Value.Replace("'", "''")
}

function Invoke-CFApi {
  param(
    [Parameter(Mandatory = $true)][ValidateSet("GET", "POST", "PATCH", "PUT", "DELETE")][string]$Method,
    [Parameter(Mandatory = $true)][string]$Path,
    [object]$Body = $null
  )

  $uri = "https://api.cloudflare.com/client/v4$Path"
  $headers = @{
    Authorization = "Bearer $script:CloudflareApiToken"
    "Content-Type" = "application/json"
  }
  $params = @{
    Method = $Method
    Uri = $uri
    Headers = $headers
    ErrorAction = "Stop"
  }
  if ($null -ne $Body) {
    $params.Body = ($Body | ConvertTo-Json -Depth 50)
  }

  try {
    $response = Invoke-RestMethod @params
  } catch {
    $detail = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
    throw "Cloudflare API failed: $Method $Path :: $detail"
  }

  if ($response.PSObject.Properties["success"] -and -not $response.success) {
    throw "Cloudflare API returned success=false: $Method $Path :: $(($response.errors | ConvertTo-Json -Depth 20))"
  }
  return $response.result
}

function Invoke-GraphApi {
  param(
    [Parameter(Mandatory = $true)][ValidateSet("GET", "POST", "PATCH", "PUT", "DELETE")][string]$Method,
    [Parameter(Mandatory = $true)][string]$Uri,
    [object]$Body = $null
  )

  $params = @{ Method = $Method; Uri = $Uri }
  if ($null -ne $Body) {
    $params.Body = ($Body | ConvertTo-Json -Depth 50)
    $params.ContentType = "application/json"
  }

  try {
    return Invoke-MgGraphRequest @params
  } catch {
    $detail = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
    throw "Microsoft Graph API failed: $Method $Uri :: $detail"
  }
}

function Ensure-DashboardSsoConnector {
  param([string]$AccountId, [string]$EmailDomain)

  if (-not $Apply) {
    Write-Plan "Would create/locate Dashboard SSO connector for $EmailDomain on Cloudflare account $AccountId."
    if ($EnableDashboardSso) { Write-Plan "Would attempt to enable Dashboard SSO after connector lookup/create." }
    return @{ id = "PLAN_ONLY"; enabled = $false; email_domain = $EmailDomain; verification = @{ code = "TXT shown after apply"; status = "pending" } }
  }

  Write-Step "Ensuring Dashboard SSO connector for $EmailDomain"
  $connectors = @(Invoke-CFApi -Method GET -Path "/accounts/$AccountId/sso_connectors")
  $connector = $connectors | Where-Object { $_.email_domain -eq $EmailDomain } | Select-Object -First 1

  if (-not $connector) {
    $connector = Invoke-CFApi -Method POST -Path "/accounts/$AccountId/sso_connectors" -Body @{ email_domain = $EmailDomain }
  }

  if ($EnableDashboardSso) {
    Write-Step "Enabling Dashboard SSO for $EmailDomain"
    $connector = Invoke-CFApi -Method PATCH -Path "/accounts/$AccountId/sso_connectors/$($connector.id)" -Body @{ enabled = $true }
  } else {
    Write-Host "Leaving Dashboard SSO disabled unless it was already enabled. Use -EnableDashboardSso only after TXT verification and IdP test." -ForegroundColor Yellow
  }
  return $connector
}

function Get-ScimToken {
  param([object]$Account, [bool]$CreateIfMissing)

  $accountId = [string]$Account.accountId
  $name = [string](Get-PropertyValue $Account "name" $accountId)

  $envVar = Get-PropertyValue $Account "scimApiTokenEnvVar" $null
  if ($envVar) {
    $token = [Environment]::GetEnvironmentVariable([string]$envVar)
    if ($token) { return $token }
    throw "Account '$name' references scimApiTokenEnvVar '$envVar', but the environment variable is empty."
  }

  $plainToken = Get-PropertyValue $Account "scimApiToken" $null
  if ($plainToken) {
    Write-Warning "Account '$name' includes scimApiToken directly in config. Prefer scimApiTokenEnvVar."
    return [string]$plainToken
  }

  if (-not $CreateIfMissing) {
    throw "Account '$name' needs scimApiTokenEnvVar/scimApiToken, or set cloudflare.createScimTokens=true."
  }

  if (-not $Apply) {
    Write-Plan "Would create Cloudflare Account API token with 'SCIM Provisioning Edit' for account '$name'."
    return "PLAN_ONLY_TOKEN"
  }

  Write-Step "Creating SCIM Provisioning API token for Cloudflare account '$name'"
  $permissionGroups = @(Invoke-CFApi -Method GET -Path "/accounts/$accountId/tokens/permission_groups")
  $scimPermission = $permissionGroups | Where-Object { $_.name -eq "SCIM Provisioning Edit" } | Select-Object -First 1
  if (-not $scimPermission) {
    throw "Could not find Cloudflare permission group 'SCIM Provisioning Edit' for account '$name'."
  }

  $resources = @{}
  $resources["com.cloudflare.api.account.$accountId"] = "*"
  $tokenBody = @{
    name = "SCIM Provisioning - $name - $(Get-Date -Format yyyyMMddHHmmss)"
    policies = @(@{
      effect = "allow"
      permission_groups = @(@{ id = $scimPermission.id })
      resources = $resources
    })
  }

  $expiresOn = Get-PropertyValue $script:Config.cloudflare "scimTokenExpiresOn" $null
  if ($expiresOn) { $tokenBody.expires_on = [string]$expiresOn }

  $created = Invoke-CFApi -Method POST -Path "/accounts/$accountId/tokens" -Body $tokenBody
  if (-not $created.value) { throw "Cloudflare created a token for '$name' but did not return a token value." }
  return [string]$created.value
}

function Find-ServicePrincipalByDisplayName {
  param([string]$DisplayName)

  $escaped = Escape-ODataString $DisplayName
  $filter = [System.Uri]::EscapeDataString("displayName eq '$escaped'")
  $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter&`$select=id,displayName,appId,appRoleAssignmentRequired"
  $result = Invoke-GraphApi -Method GET -Uri $uri
  return @($result.value) | Select-Object -First 1
}

function Ensure-EntraScimApplication {
  param([object]$Account)

  $accountId = [string]$Account.accountId
  $name = [string](Get-PropertyValue $Account "name" $accountId)
  $prefix = [string](Get-PropertyValue $script:Config.entra "appDisplayNamePrefix" "Cloudflare SCIM - ")
  $displayName = [string](Get-PropertyValue $Account "enterpriseAppDisplayName" ($prefix + $name))
  $templateId = [string](Get-PropertyValue $script:Config.entra "nonGalleryTemplateId" "8adf8e6e-67b2-4cf2-a259-e3dc5476c621")

  if (-not $Apply) {
    Write-Plan "Would create/locate Entra Enterprise Application '$displayName'."
    return @{ id = "PLAN_ONLY_SP"; displayName = $displayName; appId = "PLAN_ONLY_APPID" }
  }

  $servicePrincipal = Find-ServicePrincipalByDisplayName -DisplayName $displayName
  if ($servicePrincipal) {
    Write-Step "Found existing Entra Enterprise Application '$displayName'"
    return $servicePrincipal
  }

  Write-Step "Creating Entra non-gallery Enterprise Application '$displayName'"
  $created = Invoke-GraphApi -Method POST -Uri "https://graph.microsoft.com/v1.0/applicationTemplates/$templateId/instantiate" -Body @{ displayName = $displayName }
  return $created.servicePrincipal
}

function Ensure-ScimJob {
  param([string]$ServicePrincipalId)

  if (-not $Apply) {
    Write-Plan "Would create/locate Entra SCIM synchronization job for servicePrincipal $ServicePrincipalId."
    return @{ id = "PLAN_ONLY_JOB"; templateId = "scim" }
  }

  $jobs = Invoke-GraphApi -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/synchronization/jobs"
  $job = @($jobs.value) | Where-Object { $_.templateId -eq "scim" } | Select-Object -First 1
  if ($job) { return $job }

  Write-Step "Creating Entra SCIM synchronization job"
  return Invoke-GraphApi -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/synchronization/jobs" -Body @{ templateId = "scim" }
}

function Set-ScimSecrets {
  param([string]$ServicePrincipalId, [string]$BaseAddress, [string]$SecretToken)

  if (-not $Apply) {
    Write-Plan "Would configure Entra SCIM BaseAddress '$BaseAddress' and SecretToken on servicePrincipal $ServicePrincipalId."
    return
  }

  Write-Step "Configuring Entra SCIM endpoint and secret"
  [void](Invoke-GraphApi -Method PUT -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/synchronization/secrets" -Body @{
    value = @(
      @{ key = "BaseAddress"; value = $BaseAddress },
      @{ key = "SecretToken"; value = $SecretToken }
    )
  })
}

function Assign-PrincipalsToEnterpriseApp {
  param([string]$ServicePrincipalId, [object]$Account)

  $name = [string](Get-PropertyValue $Account "name" $Account.accountId)
  $principalIds = @(@(Get-PropertyValue $Account "groupObjectIds" @()) + @(Get-PropertyValue $Account "userObjectIds" @())) |
    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
    Select-Object -Unique

  if (-not $principalIds -or $principalIds.Count -eq 0) {
    Write-Host "No groupObjectIds/userObjectIds listed for '$name'; skipping Entra assignments." -ForegroundColor DarkYellow
    return
  }

  if (-not $AssignPrincipals) {
    Write-Plan "Principals are listed for '$name', but -AssignPrincipals was not provided. Skipping assignments."
    return
  }

  if (-not $Apply) {
    Write-Plan "Would require assignment and assign $($principalIds.Count) Entra principal(s) to servicePrincipal $ServicePrincipalId."
    return
  }

  Write-Step "Assigning $($principalIds.Count) Entra principal(s) to '$name' app"
  [void](Invoke-GraphApi -Method PATCH -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId" -Body @{ appRoleAssignmentRequired = $true })

  foreach ($principalId in $principalIds) {
    try {
      [void](Invoke-GraphApi -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignedTo" -Body @{
        principalId = [string]$principalId
        resourceId = $ServicePrincipalId
        appRoleId = "00000000-0000-0000-0000-000000000000"
      })
    } catch {
      if ($_.Exception.Message -match "already exists|Permission being assigned already exists|Conflict") {
        Write-Host "Assignment already exists for principal $principalId" -ForegroundColor DarkGray
      } else {
        throw
      }
    }
  }
}

function Start-ScimProvisioningJob {
  param([string]$ServicePrincipalId, [string]$JobId)

  if (-not $StartProvisioning) {
    Write-Plan "Provisioning job $JobId left stopped. Use -StartProvisioning after validating mappings and assignments."
    return
  }

  if (-not $Apply) {
    Write-Plan "Would start Entra provisioning job $JobId."
    return
  }

  Write-Step "Starting Entra provisioning job $JobId"
  [void](Invoke-GraphApi -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/synchronization/jobs/$JobId/start")
}

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "ConfigPath not found: $ConfigPath" }
$script:Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if (-not $Config.cloudflare -or -not $Config.entra -or -not $Config.accounts) { throw "Config must include cloudflare, entra, and accounts." }

$ssoAccountId = [string](Get-PropertyValue $Config.cloudflare "ssoAccountId" "")
$emailDomain = [string](Get-PropertyValue $Config.cloudflare "emailDomain" "")
$apiTokenEnvVar = [string](Get-PropertyValue $Config.cloudflare "apiTokenEnvVar" "CLOUDFLARE_API_TOKEN")
$createScimTokens = [bool](Get-PropertyValue $Config.cloudflare "createScimTokens" $false)

Write-Step "Topology"
Write-Host "SSO connector account: $ssoAccountId"
Write-Host "SSO email domain:     $emailDomain"
Write-Host "SCIM accounts:        $($Config.accounts.Count)"
Write-Host "Apply changes:        $($Apply.IsPresent)"
Write-Host "Enable SSO:           $($EnableDashboardSso.IsPresent)"
Write-Host "Assign principals:    $($AssignPrincipals.IsPresent)"
Write-Host "Start provisioning:   $($StartProvisioning.IsPresent)"

if (-not $Apply) {
  foreach ($account in $Config.accounts) {
    $accountName = [string](Get-PropertyValue $account "name" $account.accountId)
    $appName = [string](Get-PropertyValue $account "enterpriseAppDisplayName" ([string](Get-PropertyValue $Config.entra "appDisplayNamePrefix" "Cloudflare SCIM - ") + $accountName))
    Write-Plan "Account '$accountName' ($($account.accountId)): Entra app '$appName', SCIM URL https://api.cloudflare.com/client/v4/accounts/$($account.accountId)/scim/v2"
  }
  return
}

if ([string]::IsNullOrWhiteSpace($ssoAccountId) -or [string]::IsNullOrWhiteSpace($emailDomain)) {
  throw "cloudflare.ssoAccountId and cloudflare.emailDomain are required."
}

$script:CloudflareApiToken = [Environment]::GetEnvironmentVariable($apiTokenEnvVar)
if ([string]::IsNullOrWhiteSpace($script:CloudflareApiToken)) {
  throw "Cloudflare API token environment variable '$apiTokenEnvVar' is empty."
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
  throw "Microsoft.Graph.Authentication module is missing. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$tenantId = [string](Get-PropertyValue $Config.entra "tenantId" "")
if ([string]::IsNullOrWhiteSpace($tenantId)) { throw "entra.tenantId is required." }

Write-Step "Connecting to Microsoft Graph tenant $tenantId"
Connect-MgGraph -TenantId $tenantId -Scopes $GraphScopes -NoWelcome | Out-Null

$state = [ordered]@{
  generatedAt = (Get-Date).ToUniversalTime().ToString("o")
  dashboardSso = $null
  accounts = @()
  notes = @(
    "SCIM API token values are not written to this state file.",
    "Dashboard SSO should only be enabled after TXT verification and IdP test succeeds.",
    "After SCIM sync, assign Cloudflare Permission Policies to the synced User Groups in each account."
  )
}

$connector = Ensure-DashboardSsoConnector -AccountId $ssoAccountId -EmailDomain $emailDomain
$verificationCode = $null
$verificationStatus = $null
if ($connector.verification) {
  $verificationCode = Get-PropertyValue $connector.verification "code" $null
  $verificationStatus = Get-PropertyValue $connector.verification "status" $null
}
$state.dashboardSso = [ordered]@{
  accountId = $ssoAccountId
  emailDomain = $emailDomain
  connectorId = $connector.id
  enabled = $connector.enabled
  verificationStatus = $verificationStatus
  verificationTxtValue = $verificationCode
}

if ($verificationCode -and -not $connector.enabled) {
  Write-Host "Create this TXT value on the email domain before enabling Dashboard SSO: $verificationCode" -ForegroundColor Yellow
}

foreach ($account in $Config.accounts) {
  $accountId = [string]$account.accountId
  if ([string]::IsNullOrWhiteSpace($accountId)) { throw "Every account entry needs accountId." }
  $accountName = [string](Get-PropertyValue $account "name" $accountId)

  Write-Step "Configuring SCIM for Cloudflare account '$accountName' ($accountId)"
  $scimToken = Get-ScimToken -Account $account -CreateIfMissing $createScimTokens
  $servicePrincipal = Ensure-EntraScimApplication -Account $account
  $job = Ensure-ScimJob -ServicePrincipalId $servicePrincipal.id

  $baseAddress = "https://api.cloudflare.com/client/v4/accounts/$accountId/scim/v2"
  Set-ScimSecrets -ServicePrincipalId $servicePrincipal.id -BaseAddress $baseAddress -SecretToken $scimToken
  Assign-PrincipalsToEnterpriseApp -ServicePrincipalId $servicePrincipal.id -Account $account
  Start-ScimProvisioningJob -ServicePrincipalId $servicePrincipal.id -JobId $job.id

  $state.accounts += [ordered]@{
    accountId = $accountId
    name = $accountName
    scimBaseAddress = $baseAddress
    entraEnterpriseAppDisplayName = $servicePrincipal.displayName
    entraServicePrincipalId = $servicePrincipal.id
    entraAppId = $servicePrincipal.appId
    synchronizationJobId = $job.id
    assignedGroupObjectIds = @(Get-PropertyValue $account "groupObjectIds" @())
    assignedUserObjectIds = @(Get-PropertyValue $account "userObjectIds" @())
  }
}

$state | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $StatePath -Encoding UTF8
Write-Step "Done. Wrote redacted state to $StatePath"
Write-Host "Next: validate Entra provisioning mappings, start jobs if not already started, then assign Cloudflare Permission Policies to synced User Groups in each account." -ForegroundColor Green
