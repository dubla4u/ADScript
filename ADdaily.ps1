#Variables
param(
    [string] $exportPath = "C:\temp\PSExport\${Env:ComputerName}\$(get-date -f yyyy-MM-dd)",
    [int] $daysInactive = 61
)
Import-Module ActiveDirectory
function folderCheck ($path)
	{
    $pathTest = Test-Path -Path $path
    if ($pathTest -eq $true)
        {
            echo "Verified $path exists"
        }
    elseif ($pathTest -ne $true)
        {
            echo "$path does not exisit. Creating $path now"
            New-Item -ItemType Directory -Path $path
        }
	}
#all variables created here
$time = (Get-Date).AddDays(-($daysInactive))
   #gather all Groups
echo "Gathering list of AD Groups"
$adGroupList = Get-ADGroup -Filter * -Properties *
   #gather all enabled users in AD
echo "Gathering list of all enabled users"
$userList = Get-ADUser -Filter {enabled -eq $true} -Properties *
   #get list of GPO
echo "Gathering list of all GPOs"
$gpos = Get-GPO -All
   #get inactive items
echo "Gathering list of all inactive users"
$inactiveUsers = Get-ADUser -Filter{LastLogonTimeStamp -le $time -and enabled -eq $true} -Properties *
   #get inactive computers
echo "Gathering list of all inactive computers"
$inactiveComputers = Get-ADComputer -Filter {LastLogonDate -le $time} -Properties *
   #get disabled items
echo "Gathering all disabled users"
$disabledUsers = Get-ADUser -Filter {enabled -eq $false} -Properties *
echo "Gathering all disabled computers"
$disabledComputers = Get-ADComputer -Filter {enabled -eq $false} -Properties *
#check for directories
echo "Checking directories now"
folderCheck -path $exportPath
folderCheck -path "$exportPath\Inactive Items"

#export group lists
echo "Exporting inactive users"
$inactiveUsers|select givenname,surname,name,samaccountname,enabled,@{Name="Stamp"; expression={[DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('yyyy-MM-dd_hh:mm:ss')}},DistinguishedName|Export-Csv -Path "$exportPath\Inactive Items\Inactive Users.csv" -NoTypeInformation
echo "Exporting inactive computers"
$inactiveComputers|select name,DistinguishedName,LastLogonDate| export-csv -path "$exportPath\Inactive Items\Inactive Computers.csv" -NoTypeInformation
echo "Exporting disabled users"
$disabledUsers|select givenname,surname,name,samaccountname,enabled|Export-Csv -Path "$exportPath\Disabled Items\Disabled Users.csv" -NoTypeInformation
echo "Exporting disabled computers"
$disabledComputers|select name,DistinguishedName,LastLogonDate,Enabled|Export-Csv -Path "$exportPath\Disabled Items\Disabled Computers.csv" -NoTypeInformation
echo "Gathering all Domain Controllers"
$dcs = (Get-ADDomain).ReplicaDirectoryServers
$dcs += (Get-ADDomain).ReadOnlyReplicaDirectoryServers
Foreach ($dc in $dcs)
	{
    echo "Gathering information for $dc"
    Get-ADDomainController -Identity $dc|Export-Csv "$exportPath\DC Information\DC Information.csv" -Append -NoTypeInformation
    echo "Running dcdiag on $dc"
    dcdiag /s:$dc > "$exportPath\DC Information\$dc.txt"
	}
echo "Gathering FSMO roles"
NetDOM /query FSMO > "$exportPath\DC Information\FSMO.txt"
echo "Gathering Replication Status for domain"
Get-ADReplicationFailure -Scope Domain|Export-Csv -Path "$exportPath\DC Information\Replication Status.csv" -NoTypeInformation

echo "Checking for accounts with non-expiring passwords"
Search-ADAccount -PasswordNeverExpires | FT Name,ObjectClass -A | Out-File $exportPath\PWnoExpire.txt

echo "Checking for up to date operating systems"
Get-AdComputer -Filter * -Property * | Sort OperatingSystem | Format-Table Name,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion,Lastlogondate -Wrap -Auto | Out-File $exportPath\OSupToDate.txt

$then = (Get-Date).AddDays(-61)
echo "Creating Old Computers Text File"
Get-ADComputer -Property Name,lastLogonDate,DistinguishedName -Filter {Enabled -eq "True" -and lastLogonDate -lt $then} | FT Name,lastLogonDate,DistinguishedName > $exportPath\ESI_Old_Computers.txt
echo "Creating Old Users Text File"
Get-ADUser -Property Name,lastLogonDate,DistinguishedName -Filter {Enabled -eq "True" -and lastLogonDate -lt $then} | FT Name,lastLogonDate,DistinguishedName > $exportPath\ESI_Old_Users.txt
echo "Exporting Administrators Group to Text file"
Get-ADGroupMember "Administrators" | FORMAT-Table > $exportPath\ESI_Administrators_Group.txt
echo "Exporting Domain Administrators Group to Text file"
Get-ADGroupMember "Domain Admins" | FORMAT-Table > $exportPath\ESI_Domain_Admins_Group.txt
echo "Exporting Enterprise Administrators Group to Text file"
Get-ADGroupMember "Enterprise Admins" | FORMAT-Table > $exportPath\ESI_Enterprise_Admins_Group.txt
echo "Exporting Exchange Trusted Subsystem Group to Text file"
Get-ADGroupMember "Exchange Trusted Subsystem" | FORMAT-Table > $exportPath\ESI_Exchange_Trusted_Subsystem_Group.txt
echo "Exporting Organization Management Group to Text file"
Get-ADGroupMember "Organization Management" | FORMAT-Table > $exportPath\ESI_Organization_Management_Group.txt
echo "Exporting SSLPVN-Users Group to Text file"
Get-ADGroupMember "SSLVPN-Users" | FORMAT-Table > $exportPath\ESI_SSLVPN-Users_Groups.txt
Get-PSDRIVE | FORMAT-Table > $exportPath\Disks.Txt
echo "Writing disk space to text file"
echo "All Items have been exported Succesfully. Have a great day!"
