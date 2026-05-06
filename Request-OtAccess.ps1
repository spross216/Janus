# Zero Trust OT Gateway — Proof of Concept
#
# Demonstrates identity-based admission control for OT device access.
# Three gates in sequence: device known → user in required group → device compliant
# If all three pass, access is admitted and a session ID is issued.
# Every decision — admit or deny — is written to the audit log.
#
# A SWE extending this would replace the stub tunnel comment in Request-OtAccess
# with real transport (TCP proxy, WireGuard tunnel, SSH forward, etc.)
#
# Usage:
#   $graph = New-GraphClient
#   & $graph.Connect
#   Request-OtAccess -DeviceId 'ot-cnc-01' -Upn 'jsmith@contoso.com' -Graph $graph
#   & $graph.Disconnect
#
# Or run directly (handles connect/disconnect automatically):
#   .\Request-OtAccess.ps1 -DeviceId 'ot-cnc-01' -Upn 'jsmith@contoso.com'

param(
    [string]$DeviceId,
    [string]$Upn,
    [hashtable]$Graph        = $null,
    [string]$RegistryPath    = "$PSScriptRoot/devices.json",
    [string]$AuditPath       = "$PSScriptRoot/audit.log"
)

#region Functional core
# Pure functions — no I/O, no Graph calls, fully testable in isolation

function Find-OtDevice {
    param([object[]]$Registry, [string]$DeviceId)
    $Registry | Where-Object { $_.deviceId -eq $DeviceId } | Select-Object -First 1
}

function Test-GroupMembership {
    param([object[]]$MemberOf, [string]$RequiredGroup)
    $null -ne ($MemberOf | Where-Object { $_.AdditionalProperties['displayName'] -eq $RequiredGroup } | Select-Object -First 1)
}

function Test-IntuneCompliance {
    param([object[]]$Devices)
    ($Devices | Where-Object { $_.ComplianceState -eq 'compliant' }).Count -gt 0
}

function New-AdmitResult {
    param([string]$Upn, [object]$Device)
    [pscustomobject]@{
        Decision   = 'Admit'
        SessionId  = [System.Guid]::NewGuid().ToString()
        Upn        = $Upn
        DeviceId   = $Device.deviceId
        DeviceName = $Device.displayName
        Location   = $Device.location
        Protocol   = $Device.protocol
        IpAddress  = $Device.ipAddress
        ExpiresAt  = (Get-Date).ToUniversalTime().AddHours(8).ToString('o')
        Reason     = $null
    }
}

function New-DenyResult {
    param([string]$Upn, [string]$DeviceId, [string]$DeviceName, [string]$Reason)
    [pscustomobject]@{
        Decision   = 'Deny'
        SessionId  = $null
        Upn        = $Upn
        DeviceId   = $DeviceId
        DeviceName = $DeviceName
        Location   = $null
        Protocol   = $null
        IpAddress  = $null
        ExpiresAt  = $null
        Reason     = $Reason
    }
}

function New-AuditEntry {
    param([pscustomobject]$Result)
    [pscustomobject]@{
        Timestamp  = (Get-Date).ToUniversalTime().ToString('o')
        Decision   = $Result.Decision
        SessionId  = $Result.SessionId
        Upn        = $Result.Upn
        DeviceId   = $Result.DeviceId
        DeviceName = $Result.DeviceName
        Reason     = $Result.Reason
    }
}

#endregion

#region Imperative shell
# I/O and side effects live here — registry reads, Graph calls, audit writes

function Get-DeviceRegistry {
    param([string]$Path)
    Get-Content -Path $Path -Raw | ConvertFrom-Json
}

function Write-AuditLog {
    param([pscustomobject]$Entry, [string]$Path)
    $Entry | ConvertTo-Json -Compress | Add-Content -Path $Path -Encoding utf8
}

function New-GraphClient {
    return @{
        Connect    = { Connect-MgGraph -Scopes @('User.Read.All', 'GroupMember.Read.All', 'DeviceManagementManagedDevices.Read.All') -NoWelcome }
        MemberOf   = { param($upn) Get-MgUserMemberOf -UserId $upn -All }
        Devices    = { param($upn) Get-MgDeviceManagementManagedDevice -Filter "userPrincipalName eq '$upn'" -All }
        Disconnect = { Disconnect-MgGraph *> $null }
    }
}

function Request-OtAccess {
    param(
        [string]$DeviceId,
        [string]$Upn,
        [hashtable]$Graph,
        [string]$RegistryPath,
        [string]$AuditPath
    )

    $registry = Get-DeviceRegistry -Path $RegistryPath
    $device   = Find-OtDevice -Registry $registry -DeviceId $DeviceId

    if (-not $device) {
        $result = New-DenyResult -Upn $Upn -DeviceId $DeviceId -DeviceName '(unknown)' `
                                 -Reason "Device '$DeviceId' not in registry"
        Write-AuditLog -Entry (New-AuditEntry $result) -Path $AuditPath
        return $result
    }

    $memberOf = & $Graph.MemberOf $Upn
    if (-not (Test-GroupMembership -MemberOf $memberOf -RequiredGroup $device.requiredGroup)) {
        $result = New-DenyResult -Upn $Upn -DeviceId $DeviceId -DeviceName $device.displayName `
                                 -Reason "Not a member of '$($device.requiredGroup)'"
        Write-AuditLog -Entry (New-AuditEntry $result) -Path $AuditPath
        return $result
    }

    $intuneDevices = & $Graph.Devices $Upn
    if (-not (Test-IntuneCompliance -Devices $intuneDevices)) {
        $result = New-DenyResult -Upn $Upn -DeviceId $DeviceId -DeviceName $device.displayName `
                                 -Reason 'No compliant Intune-managed device found for user'
        Write-AuditLog -Entry (New-AuditEntry $result) -Path $AuditPath
        return $result
    }

    $result = New-AdmitResult -Upn $Upn -Device $device
    Write-AuditLog -Entry (New-AuditEntry $result) -Path $AuditPath

    # TODO for SWE: open tunnel here using $result.IpAddress and $result.SessionId
    # The session ID is the correlation handle — associate all tunnel traffic with it
    # Session expires at $result.ExpiresAt — enforce this at the transport layer

    $result
}

#endregion

#region Entry point

if ($DeviceId -and $Upn) {
    $script:Graph = if ($Graph) { $Graph } else { New-GraphClient }

    try {
        & $script:Graph.Connect

        $result = Request-OtAccess -DeviceId $DeviceId -Upn $Upn -Graph $script:Graph `
                                   -RegistryPath $RegistryPath -AuditPath $AuditPath

        $result | Format-List Decision, SessionId, Upn, DeviceId, DeviceName, Location, Protocol, IpAddress, ExpiresAt, Reason

        if ($result.Decision -eq 'Admit') {
            Write-Host "ACCESS GRANTED  session=$($result.SessionId)  expires=$($result.ExpiresAt)" -ForegroundColor Green
        } else {
            Write-Host "ACCESS DENIED   reason=$($result.Reason)" -ForegroundColor Red
        }
    }
    finally {
        & $script:Graph.Disconnect
    }
}

#endregion
