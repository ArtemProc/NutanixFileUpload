Param (
  [bool]   $CommandLine              = $false,          
  [String] $ContainerName            = "Select Me",     
  [String] $SourceImagePath          = "Select Me",     
  [String] $TargetImageName          = "Enter Me",      
  [String] $TargetImageDescription   = "Enter Me",      
  [string] $PCClusterIP              = "Enter Me",      
           $PCCreds                  = (Get-credential),
  [string] $PECluster                = "Enter Me",      
  [bool]   $EULA                     = $false           
)

<#
  .SYNOPSIS
  Uploads a local Windows file to the Nutanix image catalog.

  .DESCRIPTION
  Both Commandline and UI based tool to upload ISO or Disk images to the Nutanix platform.
  Requires Prism Central.

  .PARAMETER CommandLine
  Validates input on commandline, errors out if info is missing, When false input is prompted if not specified. UI mode is default.

  .PARAMETER ContainerName
  Prism Container name to match on, can be partial string, first matching container is used, prompts for a list in UI mode.

  .PARAMETER SourceImagePath
  Full path to local file, d:\oracle.qcow, path is tested on Execution, prompted if not specified in UI mode.

  .PARAMETER TargetImageName
  Name of the image as listed in Prism, unique name is not required for Prism, just for Humans.

  .PARAMETER TargetImageDescription
  Target image description in Prism, optional value.

  .PARAMETER PCClusterIP
  ClusterIP of Prism central.

  .PARAMETER PCCreds
  PowerShell Credential object, holding Nutanix UI Prism Account, API Privileges required. (all normal UI Admins have this privilege.)

  .PARAMETER PECluster
  Partial name of the Prism Element cluster, used to find the matching Prism Element Cluster, UUID is also allowed for exact matches, prompted if not entered in UI mode.

  .PARAMETER EULA
  Use at your own risk, not Nutanix owned software.

  .INPUTS
  This tool does not support pipeline input operations

  .OUTPUTS
  Not applicable.

  .EXAMPLE
  .\NutanixFileUpload.ps1 -PCCreds $creds
  Starts the tool without Credential Prompt

  .EXAMPLE
  PS D:\GitHub\NutanixFileUpload> .\NutanixFileUpload.ps1 -PCCreds $creds -PCClusterIP 10.10.0.32 -CommandLine $true -EULA $true -ContainerName OS -SourceImagePath D:\Oracle.qcow -TargetImageName "OracleTestImage" -TargetImageDescription "Description" -PECluster mm-
  Full commandline mode

  .EXAMPLE
  C:\PS> extension "File" "doc"
  File.doc

  .LINK
  Online version: http://www.fabrikam.com/extension.html

  .LINK
  Set-Item
#>

#Prompt section
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
Add-Type -AssemblyName PresentationFramework
$global:debug = 1
### Loading Functions

Function PSR-SSL-Fix {

  try {
  add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
                                          WebRequest request, int certificateProblem) {
            return true;
        }
     }
"@

  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12

  write-log -message "SSL Certificate has been loaded." 

  } catch {

    write-log -message "SSL Certificate fix is already loaded." -sev "WARN"

  }
}

Function write-log {
  param (
  $message,
  $sev = "INFO",
  $D = 0
  ) 
  ## This write log module is designed for nutanix calm output
  if ($sev -eq "INFO" -and $Debug -ge $D){
    write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' | INFO  | $message "
  } elseif ($sev -eq "WARN"){
    write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'WARN' | $message " -ForegroundColor  Yellow
  } elseif ($sev -eq "ERROR"){
    write-host "'$(get-date -format "dd-MMM-yy HH:mm:ss")' |'ERROR'| $message " -ForegroundColor  Red
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [System.Windows.Forms.MessageBox]::Show($message,"GuestVM Tools stopped", 'OK' , 'ERROR')
    sleep 5
    [Environment]::Exit(1)
  } elseif ($sev -eq "CHAPTER"){
    write-host ""
    write-host "####################################################################"
    write-host "#                                                                  #"
    write-host "#     $message"
    write-host "#                                                                  #"
    write-host "####################################################################"
    write-host ""
  }
} 

function Get-FunctionName {
  param (
    [int]$StackNumber = 1
  ) 
    return [string]$(Get-PSCallStack)[$StackNumber].FunctionName
}

function Test-IsGuid{
  [OutputType([bool])]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]$ObjectGuid
  )
  
  # Define verification regex
  [regex]$guidRegex = '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$'

  # Check guid against regex
  return $ObjectGuid -match $guidRegex
}

Function REST-Get-PRX-Containers {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $CLUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Executing Container List"

  $URL = "https://$($PCClusterIP):9440/PrismGateway/services/rest/v1/containers?proxyClusterUuid=$CLUUID"

  try{
    $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers -ea:4;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    try {
      $task = Invoke-RestMethod -Uri $URL -method "GET" -headers $headers
    } catch {
      write-log -message "Error Caught on function $FName" -sev "ERROR"
    }
  }
  write-log -message "We found $($task.entities.count) items."

  Return $task
} 

Function REST-PRX-Get-Task {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $CLUUID,
    [string] $TaskUUID
  )
  ## This is silent on purpose
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/tasks/$($TaskUUID)?proxyClusterUuid=$($CLUUID)"


  try { 
    $task = Invoke-RestMethod -Uri $URL -method "GET"  -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "GET"  -headers $headers

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

  }
  Return $task
} 

Function REST-Image-Import-PC {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser,
    [string] $failsilent,
    [String] $PEclusterUUID
  )
  write-log -message "Building Credential object"
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  do {;

    write-log -message "Building Image Import JSON" 
    $ImageURL = "https://$($PCClusterIP):9440/api/nutanix/v3/images/migrate"  
    $ImageJSON = @"
{
  "image_reference_list":[],
  "cluster_reference":{
    "uuid":"$($PEclusterUUID)",
    "kind":"cluster",
    "name":"string"}
}
"@
    $countimport++;
    $successImport = $false;
    try {;
      $task = Invoke-RestMethod -Uri $ImageURL -method "post" -body $ImageJSON -ContentType 'application/json' -headers $headers -ea:4;
      $successImport = $true
    } catch {$error.clear();

      write-log -message "Importing Images into PC Failed, retry attempt '$countimport' out of '$failcount'" -sev "WARN";

      sleep 60
      $successImport = $false;
    }
  } until ($successImport -eq $true -or $countimport -eq $failcount);

  if ($successImport -eq $true){
    write-log -message "Importing Images into PC success"
    $status = "Success"
  } else {
    $status = "Failed"
  }
  $resultobject =@{
    Result = $status
    TaskUUID = $task.task_uuid
  }
  return $resultobject
};

Function REST-PRX-Create-Local-Image {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [string] $ImageName,
    [string] $ImageDescription,
    [string] $ImageType = "DISK_IMAGE", # or ISO_IMAGE
    [string] $CLUUID
  )

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }
  
  $URL = "https://$($PCClusterIP):9440/api/nutanix/v0.8/images?proxyClusterUuid=$($CLUUID)"
  
  $json = @"
{
  "name": "$($ImageName)",
  "annotation": "$($ImageDescription)",
  "imageType": "$($ImageType)"
}
"@
  try{
    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json'  -headers $headers;
  } catch {
    sleep 10

    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"

    $task = Invoke-RestMethod -Uri $URL -method "POST" -body $json -ContentType 'application/json' -headers $headers;
  }

  Return $task
} 

Function REST-PRX-Upload-Local-Image {
  Param (
    [string] $PxClusterUser,
    [string] $PxClusterPass,
    [string] $PCClusterIP,
    [string] $SourceImagePath,
    [string] $ImageUUID,
    [object] $Creds,
    [STRING] $CLUUID,
    [string] $containerUUID
  )
  
  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{
    Authorization = "Basic $encodedCredentials"
    'X-Nutanix-Destination-Container' = $containerUUID
  }

  $url = "https://$($PCClusterIP):9440/api/nutanix/v0.8/images/$($imageuuid)/upload?proxyClusterUuid=$CLUUID"

  write-log -message "Sending image to Container UUID '$containerUUID'"
  write-log -message "Updating Image UUID '$($imageuuid)'"

  try{
  
    $task = invoke-RestMethod -Uri $url -Credential $Creds -InFile "$SourceImagePath" -Method PUT -ContentType "application/octet-stream" -headers $headers -ea:4
  
  } catch {
    sleep 10
  
    $FName = Get-FunctionName;write-log -message "Error Caught on function $FName" -sev "WARN"
  
    Invoke-RestMethod -Uri $url -Credential $Creds -InFile "$SourceImagePath" -Method PUT -ContentType "application/octet-stream" -headers $headers
  }

  Return $task
} 

Function REST-Query-PC-Clusters {
  Param (
    [string] $PCClusterIP,
    [string] $PxClusterPass,
    [string] $PxClusterUser
  )
  write-log -message "Building Credential object"

  $credPair = "$($PxClusterUser):$($PxClusterPass)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  write-log -message "Building Cluster Query JSON"

  $URL = "https://$($PCClusterIP):9440/api/nutanix/v3/clusters/list"
  $Payload= @{
    kind="cluster"
    offset=0
    length=99999
  } 

  $JSON = $Payload | convertto-json
  try{
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
  } catch {$error.clear()
    sleep 10
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers
  }
  if ($task.entities.count -eq 0){
    do {
      $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers -ea:4;
      sleep 30
      $count++

      write-log -message "Cycle $count Getting Clusters, current items found is '$($task.entities.count)'"
    } until ($count -ge 10 -or $task.entities.count -ge 1)
  }
  write-log -message "We found '$($task.entities.count)' clusters"

  Return $task
} 


if ($PSVersionTable.PSVersion.Major -lt 5){

  write-log -message "You need to run this on Powershell 5 or greater...." -sev "ERROR"

} elseif ($PSVersionTable.PSVersion.Major -match 5 ){

  write-log -message "Disabling SSL Certificate Check for PowerShell 5"

  PSR-SSL-Fix

}

if ($PCCreds.getnetworkcredential().password -eq $null){

  write-log -message "User canceled the credential Request" -sev "Error"
  
}

if (!$eula -and !$commandline){
  $License = [System.Windows.Forms.MessageBox]::Show("Use at your own risk, do you accept?`nThis software is NOT linked to Nutanix.", "Nutanix License" , 4)
  if ($license -eq "Yes"){
  
    write "User accepted the license"
  
  } else {
  
    [System.Windows.Forms.MessageBox]::Show($message,"User did not accept the license!","STOP",0,16)
    sleep 5
    [Environment]::Exit(1)
  
  }
} elseif (!$eula) {
  [System.Windows.Forms.MessageBox]::Show($message,"User did not accept the license!","STOP",0,16)
  sleep 5
  [Environment]::Exit(1) 
}
write-log -message "Getting some data"

$Sourceitem = get-item $SourceImagePath -ea:4

write-log -message "Validating Input" -sev "Chapter"

if ($CommandLine){

  if (!$Sourceitem -or $SourceImagePath -eq "Select Me"){

    write-log -message "The Source file '$SourceImagePath' does not exist, commandline mode does not prompt." -sev "ERROR"

  }
  if ($TargetImageName -eq "Enter Me"){

    write-log -message "Target Image name is a required property, commandline mode does not prompt." -sev "ERROR"

  }
  if ($PCClusterIP -eq "Enter Me"){

    write-log -message "PC Cluster IP is not specified, commandline mode does not prompt." -sev "ERROR"

  }
} else {

  if (!$Sourceitem){

    Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }
    $null = $FileBrowser.ShowDialog()
    $SourceImagePath = $FileBrowser.FileName
    $Sourceitem = get-item $SourceImagePath -ea:4 

  }
  if ($PCClusterIP -eq "Enter Me"){
    $PCClusterIP = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Prism Central IP", "Prism Central IP address", "")
  }
  if ($TargetImageName -eq "Enter Me"){
    $TargetImageName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Prism Image Name", "Image Catalog Name", "")
  }
}

$PCClusters = REST-Query-PC-Clusters `
  -PCClusterIP $PCClusterIP `
  -PxClusterUser $PCCreds.getnetworkcredential().username `
  -PxClusterPass $PCCreds.getnetworkcredential().password

if ($guidtest = Test-IsGuid $PECluster){
  $PEClusterObj = $PCClusters.entities | where {$_.metadata.uuid -eq $PECluster}
} else {
  $PEClusterObj = $PCClusters.entities | where {$_.status.name -match $PECluster} | select -first 1
}

if ($commandline){
    if ($PECluster -eq "Enter Me"){

    write-log -message "PE Cluster Name or UUID is not specified, commandline mode does not prompt." -sev "ERROR"

    sleep 5
    [Environment]::Exit(1)    

  }
} else {
  if ($PECluster -eq "Enter Me" -or !$PEcluster){

    write-log -message "PE Cluster Name, UUID is not specified or cluster cannot be found."
    $GridArguments = @{
      OutputMode = 'Single'
      Title      = 'Select the Nutanix Prism Element Cluster and click OK'
    }
    [object]$custom = $null
    [array]$customPCs = $null
    $PCClusters.entities | where {$_.status.name -ne "Unnamed" } | % {
      $custom = New-Object -Type PSObject
      $custom | add-member NoteProperty Name $_.status.Name
      $custom | add-member NoteProperty ClusterUUID $_.metadata.uuid
      $customPCs += $custom
    }
    do {
      $PESelect = ($customPCs  | Out-GridView @GridArguments)
    } until ($PESelect)
    sleep 5
    write-log -message "We selected '$($PESelect.ClusterUUID)'"
    $PEClusterObj = $PCClusters.entities | where {$_.metadata.uuid -eq $PESelect.ClusterUUID}
  } 
}

if (!$PEClusterObj.metadata.uuid){
  write-log -message "We cannot find the PE cluster, whats wrong here." -sev "ERROR"
} else {
  write-log -message "Using PE Cluster '$($PEClusterObj.metadata.uuid)'"
}

$containers = REST-Get-PRX-Containers `
  -PCClusterIP $PCClusterIP `
  -PxClusterUser $PCCreds.getnetworkcredential().username `
  -PxClusterPass $PCCreds.getnetworkcredential().password `
  -CLUUID $PEClusterObj.metadata.uuid

$containerobj = $containers.entities | where {$_.name -match $ContainerName} | select -first 1

if ($commandline){
  if (!$containerobj){
    write-log -message "The Nutanix Container '$ContainerName' does not exist, commandline mode does not prompt." -sev "ERROR"
    sleep 5
    [Environment]::Exit(1)    
  }
} else {
  if (!$containerobj){
    $GridArguments = @{
      OutputMode = 'Single'
      Title      = 'Select the Nutanix Storage Container and click OK'
    }
    do {
      $ContainerSelect = ($containers.entities | select name, ContainerUUID | Out-GridView @GridArguments)
    } until ($ContainerSelect)
    $containerobj = $containers.entities | where {$_.ContainerUUID -eq $ContainerSelect.ContainerUUID} 
  }  
}

if ($TargetImageDescription -eq "Enter Me"){
  $TargetImageDescription = ""
}
$ImageExtention = $SourceImagePath.split(".") | select -last 1
if ($ImageExtention -eq "iso"){
  $DiskType = "ISO_IMAGE"
} else {
  $DiskType = "DISK_IMAGE"
}

write-log -message "Creating Var object." -sev "Chapter"

$vars = @{
  PCClusterIP   = $PCClusterIP
  PCCreds       = $PCCreds
  CLUUID        = $PEClusterObj.metadata.uuid
  ContainerUUID = $containerobj.ContainerUUID
}

write-log -message "Creating Image" -sev "Chapter"

write-log -message "Creating Empty Image Object (hidden)"

$task = REST-PRX-Create-Local-Image `
  -PCClusterIP $vars.PCClusterIP `
  -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
  -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
  -CLUUID $vars.CLUUID `
  -ImageName $TargetImageName `
  -ImageDescription $TargetImageDescription `
  -ImageType $DiskType

sleep 4
write-log -message "Lets get the image UUID through the task UUID: '$($task.taskuuid)'"

$imageTask = REST-PRX-Get-Task `
  -PCClusterIP $vars.PCClusterIP `
  -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
  -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
  -CLUUID $vars.CLUUID `
  -TaskUUID $task.taskuuid

$Seconds = $Sourceitem.Length /1MB
$minutes = $Seconds/60

write-log -message "Uploading Image" -sev "Chapter"
write-log -message "Sending payload to the image object '$($imageTask.entity_reference_list.uuid)'"
write-log -message "Estimated transfer of this file is '$($minutes)' Minutes, function is capped to 1MBs"

$Upload = REST-PRX-Upload-Local-Image `
  -PCClusterIP $vars.PCClusterIP `
  -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
  -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
  -CLUUID $vars.CLUUID `
  -SourceImagePath $SourceImagePath `
  -ImageUUID $imageTask.entity_reference_list.uuid `
  -Creds $vars.PCCreds `
  -ContainerUUID $vars.ContainerUUID

write-log -message "Importing Cluster Images into Prism Central." -sev "Chapter"

REST-Image-Import-PC `
  -PCClusterIP $vars.PCClusterIP `
  -PxClusterUser $vars.PCCreds.getnetworkcredential().username `
  -PxClusterPass $vars.PCCreds.getnetworkcredential().password `
  -PEclusterUUID $vars.CLUUID

if (!$error){
  [Environment]::Exit(1) 
}