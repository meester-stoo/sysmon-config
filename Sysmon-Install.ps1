<# This script is designed to install Sysmon from a network directory during a MDT Deployment
It also uses some tricks to ensure that the service is not "easily" discoverable. There are methods to find that sysmon is running 
but this hopefully will prevent the "fluff" from being able to find it.
By default Sysmon installs it's service using the same name as the executable it's installed as (Hence why it's renamed at source).
Additionally you can change the name of the Driver it installs (as long as it isan't the same as the service name and is 8 characters or less)
Finally adding some generic Service descrption, name and such helps to cover it up as well. There is also the option to set the ACL's on the service itself.
Still looking at how to Hide the actual Sysmon eventlog, but that will probably be an ACL as well
I have commented out the admin consent configuration because a default windows 10 in a clean MDT deployment doesn't worry about that.
#>

$RootDir = "<installerdir>\Sysmon"
#Permissions to Set on folder so that users are unable to modify/view it
$SDDL = "O:S-1-5-21-3766719631-1581505285-2304295922-1165G:DUD:PAI(A;OICIIO;FA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
#Set installation Folder and configure permissions
New-Item -Path $env:ProgramData\SysCfg -ItemType Directory -Force
$FolderSecurity = get-acl -Path $env:ProgramData\SysCfg
$FolderSecurity.SetSecurityDescriptorSddlForm($SDDL)

#copy the config file and "faux service" (renamed to not be default sysmon service)
Copy-Item $RootDir\configv7.xml -Destination $env:ProgramData\SysCfg\. -Force
Copy-Item $RootDir\RDPFltr.exe -Destination $env:ProgramData\SysCfg\. -Force
#$value = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin).ConsentPromptBehaviorAdmin
#Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
Start-Process -FilePath "$env:ProgramData\SysCfg\RDPFltr.exe" -ArgumentList "-accepteula -i .\configv7.xml -d RDPFltDv" -WorkingDirectory $env:ProgramData\SysCfg -Wait
Start-Process -FilePath 'sc.exe' -ArgumentList 'config RDPFltr displayname= "Remote Desktop Services Filter Driver"' -WindowStyle 'Hidden'
Start-Process -FilePath 'sc.exe' -ArgumentList 'description RDPFltr "Provides driver filtering to enables enhanced clipboard and display graphics for Remote Desktop Services."' -WindowStyle 'Hidden'
Start-Process -FilePath 'sc.exe' -ArgumentList 'failure RDPFltr reset= 432000 actions= restart/300000/restart/300000/restart/300000'  -WindowStyle 'Hidden'
Start-Process -FilePath 'sc.exe' -ArgumentList 'sdset RDPFltr D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)' -WindowStyle 'Hidden'
#Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value $value
Set-Acl -Path $env:ProgramData\SysCfg -AclObject $FolderSecurity
