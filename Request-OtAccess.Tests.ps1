BeforeAll {
    . "$PSScriptRoot/Request-OtAccess.ps1"
}

Describe 'Find-OtDevice' {
    BeforeAll {
        $registry = @(
            [pscustomobject]@{ deviceId = 'ot-cnc-01';  displayName = 'CNC Machine #1' }
            [pscustomobject]@{ deviceId = 'ot-weld-01'; displayName = 'Welding Robot #1' }
        )
    }

    It 'returns the matching device' {
        $result = Find-OtDevice -Registry $registry -DeviceId 'ot-cnc-01'
        $result.deviceId    | Should -Be 'ot-cnc-01'
        $result.displayName | Should -Be 'CNC Machine #1'
    }

    It 'returns null when device is not in registry' {
        Find-OtDevice -Registry $registry -DeviceId 'ot-unknown' | Should -BeNullOrEmpty
    }
}

Describe 'Test-GroupMembership' {
    BeforeAll {
        $memberOf = @(
            [pscustomobject]@{ AdditionalProperties = @{ 'displayName' = 'OT-CNC-Operators' } }
            [pscustomobject]@{ AdditionalProperties = @{ 'displayName' = 'All-Staff' } }
        )
    }

    It 'returns true when user is a member of the required group' {
        Test-GroupMembership -MemberOf $memberOf -RequiredGroup 'OT-CNC-Operators' | Should -BeTrue
    }

    It 'returns false when user is not a member of the required group' {
        Test-GroupMembership -MemberOf $memberOf -RequiredGroup 'OT-SCADA-Admins' | Should -BeFalse
    }

    It 'returns false when MemberOf is empty' {
        Test-GroupMembership -MemberOf @() -RequiredGroup 'OT-CNC-Operators' | Should -BeFalse
    }
}

Describe 'Test-IntuneCompliance' {
    It 'returns true when at least one device is compliant' {
        $devices = @(
            [pscustomobject]@{ ComplianceState = 'noncompliant' }
            [pscustomobject]@{ ComplianceState = 'compliant' }
        )
        Test-IntuneCompliance -Devices $devices | Should -BeTrue
    }

    It 'returns false when no devices are compliant' {
        $devices = @(
            [pscustomobject]@{ ComplianceState = 'noncompliant' }
            [pscustomobject]@{ ComplianceState = 'unknown' }
        )
        Test-IntuneCompliance -Devices $devices | Should -BeFalse
    }

    It 'returns false when device list is empty' {
        Test-IntuneCompliance -Devices @() | Should -BeFalse
    }
}

Describe 'New-AdmitResult' {
    BeforeAll {
        $device = [pscustomobject]@{
            deviceId    = 'ot-cnc-01'
            displayName = 'CNC Machine #1 — Bay A'
            location    = 'Manufacturing Bay A'
            protocol    = 'Modbus TCP'
            ipAddress   = '192.168.100.10'
        }
        $result = New-AdmitResult -Upn 'jsmith@contoso.com' -Device $device
    }

    It 'sets Decision to Admit' {
        $result.Decision | Should -Be 'Admit'
    }

    It 'generates a valid GUID session ID' {
        $result.SessionId | Should -Not -BeNullOrEmpty
        { [System.Guid]::Parse($result.SessionId) } | Should -Not -Throw
    }

    It 'sets ExpiresAt to approximately 8 hours from now' {
        $hours = ([DateTimeOffset]::Parse($result.ExpiresAt) - [DateTimeOffset]::UtcNow).TotalHours
        $hours | Should -BeGreaterThan 7.9
        $hours | Should -BeLessThan 8.1
    }

    It 'maps device properties from the registry entry' {
        $result.DeviceId   | Should -Be 'ot-cnc-01'
        $result.DeviceName | Should -Be 'CNC Machine #1 — Bay A'
        $result.IpAddress  | Should -Be '192.168.100.10'
        $result.Protocol   | Should -Be 'Modbus TCP'
    }

    It 'sets Reason to null' {
        $result.Reason | Should -BeNullOrEmpty
    }
}

Describe 'New-DenyResult' {
    BeforeAll {
        $result = New-DenyResult -Upn 'jsmith@contoso.com' -DeviceId 'ot-cnc-01' `
                                 -DeviceName 'CNC Machine #1' -Reason 'Not a member of OT-CNC-Operators'
    }

    It 'sets Decision to Deny' {
        $result.Decision | Should -Be 'Deny'
    }

    It 'sets SessionId to null' {
        $result.SessionId | Should -BeNullOrEmpty
    }

    It 'sets ExpiresAt to null' {
        $result.ExpiresAt | Should -BeNullOrEmpty
    }

    It 'captures the denial reason' {
        $result.Reason | Should -Be 'Not a member of OT-CNC-Operators'
    }
}

Describe 'New-AuditEntry' {
    It 'maps an Admit result to an audit entry' {
        $device = [pscustomobject]@{
            deviceId    = 'ot-cnc-01'
            displayName = 'CNC Machine #1'
            location    = 'Bay A'
            protocol    = 'Modbus TCP'
            ipAddress   = '192.168.100.10'
        }
        $admit = New-AdmitResult -Upn 'jsmith@contoso.com' -Device $device
        $entry = New-AuditEntry -Result $admit

        $entry.Timestamp | Should -Not -BeNullOrEmpty
        $entry.Decision  | Should -Be 'Admit'
        $entry.SessionId | Should -Be $admit.SessionId
        $entry.Upn       | Should -Be 'jsmith@contoso.com'
        $entry.Reason    | Should -BeNullOrEmpty
    }

    It 'maps a Deny result to an audit entry' {
        $deny  = New-DenyResult -Upn 'bjones@contoso.com' -DeviceId 'ot-cnc-01' `
                                -DeviceName 'CNC Machine #1' -Reason 'Not a member of OT-CNC-Operators'
        $entry = New-AuditEntry -Result $deny

        $entry.Timestamp | Should -Not -BeNullOrEmpty
        $entry.Decision  | Should -Be 'Deny'
        $entry.SessionId | Should -BeNullOrEmpty
        $entry.Reason    | Should -Be 'Not a member of OT-CNC-Operators'
    }
}
