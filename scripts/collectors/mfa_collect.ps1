<#
Collect users without MFA using Microsoft Graph (MSAL + Microsoft.Graph PowerShell modules recommended).
This script expects you to be logged in with Connect-MgGraph or Connect-AzAccount and have required Graph permissions.
It writes a JSON evidence file and can POST to the API if supplied with an endpoint.
#>
param(
    [string]$OutputPath = "./evidence_users_mfa.json",
    [string]$ApiEndpoint = "http://localhost:8000/evidence"
)

# Prefer Microsoft Graph module; fallback to AzureAD if needed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
    Write-Host "Microsoft.Graph.Users module not found. Please Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
}

# Try to get users
try {
    # If using Microsoft.Graph
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Users) {
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
        # Ensure there's a connection
        if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
            Write-Host "Not connected to Microsoft Graph. Run Connect-MgGraph -Scopes 'User.Read.All', 'UserAuthenticationMethod.Read.All'" -ForegroundColor Yellow
        }
        # Get users (paged)
        $users_list = Get-MgUser -All -Property Id, UserPrincipalName -ErrorAction Stop
        $users = @()
        foreach ($u in $users_list) {
            $mfa = $false
            try {
                # Prefer Get-MgUserAuthenticationMethod if available
                if (Get-Command -Name Get-MgUserAuthenticationMethod -ErrorAction SilentlyContinue) {
                    $methods = Get-MgUserAuthenticationMethod -UserId $u.Id -ErrorAction SilentlyContinue
                    if ($methods -and $methods.Count -gt 0) { $mfa = $true }
                }
                else {
                    # Fallback to REST query
                    $resp = Invoke-MgGraphRequest -Method GET -Uri ("/users/{0}/authentication/methods" -f $u.Id) -ErrorAction SilentlyContinue
                    if ($resp -and $resp.value -and $resp.value.Count -gt 0) { $mfa = $true }
                }
            }
            catch {
                # If auth method check fails, leave as false and continue
                Write-Verbose "Auth method check failed for $($u.Id): $_"
            }
            $users += [pscustomobject]@{ id = $u.Id; userPrincipalName = $u.UserPrincipalName; mfaEnabled = $mfa }
        }
    }
    else {
        # Fallback: AzureAD (deprecated) - may not show MFA state reliably
        if (Get-Module -ListAvailable -Name AzureAD) {
            Import-Module AzureAD -ErrorAction SilentlyContinue
            $users = Get-AzureADUser -All $true | Select-Object @{Name = 'id'; Expression = { $_.ObjectId } }, @{Name = 'userPrincipalName'; Expression = { $_.UserPrincipalName } } | ForEach-Object {
                [pscustomobject]@{ id = $_.id; userPrincipalName = $_.userPrincipalName; mfaEnabled = $false }
            }
        }
        else {
            throw "No suitable module found for querying users. Install Microsoft.Graph or AzureAD modules."
        }
    }

    $evidence = @{ Source = 'EntraAPI'; QueryOrRequest = 'GET /users (with MFA check)'; Timestamp = (Get-Date).ToString('o'); RawResult = $users }
    $json = $evidence | ConvertTo-Json -Depth 5
    $json | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "Wrote evidence to $OutputPath"

    if ($PSBoundParameters.ContainsKey('ApiEndpoint') -and $ApiEndpoint) {
        Write-Host "Posting evidence to $ApiEndpoint"
        try {
            Invoke-RestMethod -Uri $ApiEndpoint -Method Post -ContentType 'application/json' -Body $json
            Write-Host "Posted evidence to API"
        }
        catch {
            Write-Warning "Failed to POST to API: $_"
        }
    }
}
catch {
    Write-Error "Error collecting MFA evidence: $_"
}
