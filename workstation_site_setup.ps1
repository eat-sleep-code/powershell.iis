# === BEGIN EXAMPLE USAGE ==============================================================================
# 
# Process-Site-Definitions-Url -xmlUrl "http://127.0.0.1/xml/site_definitions.xml" -removeSite $true;
# Process-Site-Definitions -xmlFilePath "site_definitions.xml" -overwrite $false -removeSite $false;
# New-Site -basePath "C:\SRC\" -siteName "www.example.com" -siteFolder "example.com\www" -hostHeader "www.example.local";
# Remove-Site "C:\SRC\" -siteName "www.example.com" -siteFolder "example.com\www" -hostHeader "www.example.local" -removeFiles $true;
#
# Process-TFS-Definitions-Url -xmlUrl "http://127.0.0.1/xml/tfs_definitions.xml";
# Process-TFS-Definitions "tfs_definitions.xml";
# Prepare-TFS -sourceLocation "$/path/to/server/files" -localPath "C:\SRC\EXAMPLE" -collection "http://127.0.0.1:8080/tfs";
#
# Add-SelfSignedCertificate -commonName "example" -friendlyName "example"
# === END EXAMPLE USAGE ================================================================================


Function Process-Site-Definitions-Url([string]$xmlUrl, [boolean]$overwrite = $false, [boolean]$removeSite = $false)
{
    Import-Module WebAdministration;
    $date = Get-Date; # GET CURRENT DATE
    $xmlPath = "$env:TEMP\site_definitions_" + $date.ToString("yyyyMMdd") + ".xml"; # SET THE PATH FOR THE LOCAL COPY OF THE XML FILE, IN THE USERS "TEMP" FOLDER
    $web = New-Object Net.WebClient; # CREATE THE WEB CLIENT
    # DO WE NEED TO ADD PROXY HANDLING HERE?
    $web.DownloadFile($xmlUrl, $xmlPath); # DOWNLOAD THE WEB-BASED XML FILE INTO THE USERS "TEMP FOLDER"
    Process-Site-Definitions -xmlFilePath $xmlPath -overwrite $overwrite -removeSite $removeSite; # PROCESS THE LOCAL COPY OF THE XML FILE 
    Remove-Item -Path $xmlPath; # REMOVE THE LOCAL COPY OF THE XML FILE
};





Function Process-Site-Definitions([string]$xmlFilePath = "site_definitions.xml", [boolean]$overwrite = $false, [boolean]$removeSite = $false)
{
    Import-Module WebAdministration;
    [xml]$xmlFile = Get-Content $xmlFilePath;
    foreach ($site in $xmlFile.definitions.site)
    {
        if ($removeSite -eq $true)
        {
            Remove-Site -basePath $site.basePath -siteName $site.siteName -siteFolder $site.siteFolder -hostHeader $site.hostHeader -netVersion $site.netVersion -removeFiles ([System.Convert]::ToBoolean($site.removeFilesOnSiteRemoval));
        }
        else
        {
			$basePath = $site.basePath; # USED FOR LOGGING
            $siteCount = (Get-Website | Where-Object {$_.name -eq $site.siteName}).count;
            if (($overwrite -eq $False) -and ($siteCount -gt 0))
            {
                $siteName = $site.siteName;
                Log-Text "Site Already Exists (Skipping Creation): $siteName";
            }
            else
            {
                New-Site -basePath $site.basePath -siteName $site.siteName -siteFolder $site.siteFolder -hostHeader $site.hostHeader -netVersion $site.netVersion -enable32Bit ([System.Convert]::ToBoolean($site.enable32bit)) -classicPipelineMode ([System.Convert]::ToBoolean($site.classicPipelineMode));
                # CREATE VIRTUAL DIRECTORIES
                foreach ($directory in $site.virtualDirectories.directory)
                {
                    $pathExists=Test-Path $directory.path;
                    if ($pathExists -eq $False)
                    {
                        Log-Text "Creating Folder For Virtual Directory: $directory.name";
                        New-Item $directory.path -type directory -Verbose | Log-Action;   
                    }
                    New-WebVirtualDirectory -Site $site.siteName -PhysicalPath $directory.path -Name $directory.name -Force; 
                }
            }
        }
    }
};





Function New-Site([string]$basePath = "C:\InetPub\wwwroot\", [string]$siteName, [string]$siteFolder, [string]$hostHeader, [string]$netVersion = "4.0", [boolean]$enable32Bit = $false, [boolean]$classicPipelineMode = $false)
{      
    Import-Module WebAdministration;
    
    # IF WEBSITE FOLDER DOES NOT EXIST, CREATE IT.
    $pathExists=Test-Path $basePath$siteFolder;
    if ($pathExists -eq $False)
    {
        Log-Text "Creating Folder: $basePath$siteFolder";
        New-Item $basePath$siteFolder -type directory -Verbose | Log-Action;   
    }
    # CREATE APPLICATION POOL (IF NECESSARY) AND THEN CREATE WEBSITE
    if ($netversion -eq "1.1") # ASP.NET 1.1 SITES (PLEASE STOP BUILDING THESE!)
    {
        # ONLY ONE ASP.NET 1.1 APPLICATION POOL CAN BE CREATED AND WILL BE USED BY ALL ASP.NET 1.1 APPLICATIONS
        Log-Text "Using Application Pool: ASP.NET 1.1";
        Log-Text "Creating Website: $siteName :80";
        New-Website -Name $siteName -ApplicationPool "ASP.NET 1.1" -Force -HostHeader $hostHeader -PhysicalPath $basePath$siteFolder -Port 80 -Verbose | Log-Action; # CREATE THE SITE
    }
    else # MODERN ASP.NET SITES
    {
        Log-Text "Creating Application Pool: $siteName";
        New-WebAppPool -Name $siteName -Force;
        Set-ItemProperty IIS:\AppPools\$siteName managedRuntimeVersion v$netVersion -Force -Verbose | Log-Action; # SET THE .NET RUNTIME VERSION 
        if ($enable32Bit -eq $True)
        {
           Set-ItemProperty IIS:\AppPools\$siteName enable32BitAppOnWin64 true -Force -Verbose | Log-Action; # IF APPLICABLE, ENABLE 32 BIT APPLICATIONS
        }
        if ($classicPipelineMode -eq $True)
        {
            Set-ItemProperty IIS:\AppPools\$siteName managedPipelineMode 1 -Force -Verbose | Log-Action; # IF APPLICABLE, SET TO CLASSIC PIPELINE MODE
        }
        Set-ItemProperty IIS:\AppPools\$siteName passAnonymousToken true -Force -Verbose | Log-Action; 
        Log-Text "Creating Website: $siteName :80";
        New-Website -Name $siteName -ApplicationPool $siteName -Force -HostHeader $hostHeader -PhysicalPath $basePath$siteFolder -Port 80 -Verbose | Log-Action; # CREATE THE SITE
    }
	Log-Text "Binding SSL Port: $siteName :443";
    New-WebBinding -Name $siteName -Port 443 -Protocol https -HostHeader $hostHeader -Verbose | Log-Action; # BIND THE SSL PORT (443) TO THE SITE
};





Function Remove-Site([string]$basePath = "C:\InetPub\wwwroot\", [string]$siteName, [string]$siteFolder, [string]$hostHeader, [string]$netVersion = "4.0", [boolean]$removeFiles = $false)
{      
    Import-Module WebAdministration;
    
    # REMOVE WEBSITE
    Log-Text "Removing Website: $siteName";
    Remove-Website $siteName -Verbose | Log-Action;    
    
    # IF--NON ASP.NET 1.1--APPLICATION POOL IS NOW EMPTY, REMOVE IT
    if ($netversion -ne "1.1")
    {
        if ((Get-WebApplication | where{ $_.appliationPool -eq $siteName }).count -eq 0)
        {
            Sleep 3;
            Log-Text "Removing Application Pool: $siteName";
            Remove-WebAppPool $siteName;
        }
    }

    if ($removeFiles -eq $True)
    {
        #IF SPECIFIED FOLDER EXISTS, REMOVE IT
        $pathExists=Test-Path $basePath$siteFolder;
        if ($pathExists -eq $True)
        {
            $parentFolderPath = Split-Path $basePath$siteFolder -Parent;
            Log-Text "Removing Folder:  $basePath$siteFolder";
            Remove-Item -Recurse -Force $basePath$siteFolder -Verbose | Log-Action; 
            
            #IF PARENT FOLDER IS EMPTY, REMOVE IT
            $directoryInfo = Get-ChildItem $parentFolderPath | Measure-Object;
            if ($directoryInfo.count -eq 0)
            {
                Log-Text "Removing Folder:  $parentFolderPath";
                Remove-Item -Recurse -Force $parentFolderPath  -Verbose | Log-Action; 
            }
        }
    }
   
};





Function Process-TFS-Definitions-Url([string]$xmlUrl)
{
    $date = Get-Date; # GET CURRENT DATE
    $xmlPath = "$env:TEMP\tfs_definitions_" + $date.ToString("yyyyMMdd") + ".xml"; # SET THE PATH FOR THE LOCAL COPY OF THE XML FILE, IN THE USERS "TEMP" FOLDER
    $web = New-Object Net.WebClient; # CREATE THE WEB CLIENT
    # DO WE NEED TO ADD PROXY HANDLING HERE?
    $web.DownloadFile($xmlUrl, $xmlPath); # DOWNLOAD THE WEB-BASED XML FILE INTO THE USERS "TEMP FOLDER"
    Process-TFS-Definitions -xmlFilePath $xmlPath; # PROCESS THE LOCAL COPY OF THE XML FILE 
    Remove-Item -Path $xmlPath; # REMOVE THE LOCAL COPY OF THE XML FILE
};





Function Process-TFS-Definitions([string]$xmlFilePath = "tfs_definitions.xml")
{
    [xml]$xmlFile = Get-Content $xmlFilePath;
    foreach ($map in $xmlFile.definitions.map)
    {
       Prepare-TFS -sourceLocation $map.sourceLocation -localPath $map.localPath -collection $map.collection;
    }
};





Function Prepare-TFS([string]$sourceLocation, [string]$localPath = "C:\InetPub\wwwroot\", [string]$collection)
{
    # SWITCH TO THE LOCATION OF TF.EXE (AND MAKE SURE YOU ARE ON THE "C:" DRIVE)
    CD "C:\Program Files (x86)\Microsoft Visual Studio 11.0\Common7\IDE";
    C:; 
   
    # CREATE THE LOCAL FOLDER
    MKDIR -Force -Path "$localPath";

    # MAP THE LOCAL FOLDER TO THE SERVER IN THE CURRENT WORKSPACE
    CMD /C "TF WORKFOLD /map `"$sourceLocation`" `"$localPath`" /workspace:$env:COMPUTERNAME /collection:$collection"

    # GET THE SOURCE CODE
    CMD /C "TF get `"$localPath`" /version:T /force /recursive /noprompt";

    # REMOVE LOCAL READ-ONLY BIT
    ATTRIB -R "$localPath" /S /D;

    # SET PERMISSIONS TO AVOID ISSUES WHEN MOVING CODE BETWEEN DESKTOPS AND BETWEEN SERVERS 
    CMD /C "ICACLS `"$localPath`" /GRANT `"EVERYONE`":(OI)(CI)F";

    # SET PERMISSIONS TO AVOID ISSUES WITH EXECUTING CODE ON SERVER
    CMD /C "ICACLS `"$localPath`" /GRANT `"ASPNET`":(OI)(CI)F";
    CMD /C "ICACLS `"$localPath`" /GRANT `"IIS_IUSRS`":(OI)(CI)F";
    CMD /C "ICACLS `"$localPath`" /GRANT `"NETWORK SERVICE`":(OI)(CI)F";
    CMD /C "ICACLS `"$localPath`" /GRANT `"SYSTEM`":(OI)(CI)F";
}





Function Log-Text([string]$text)
{
    $date = Get-Date;
    $logPath = $basePath + $date.ToString("yyyyMMdd") + ".log";
    $currentTime = $date.ToString("hh:mm:ss tt");
    Add-Content $logPath "`n#$currentTime`t$text`r";
    Add-Content $logPath "`n#==============================================================================`r";
};





Function Log-Action()
{
    $date = Get-Date;
    $logPath = $basePath + $date.ToString("yyyyMMdd") + ".log";
    Out-File "$logPath" -encoding ASCII -Append -NoClobber;
};





function Add-SelfSignedCertificate ([string]$commonName, [string]$friendlyName, [int]$daysUntilExpiration = 365)
{
    $name = new-object -com "X509Enrollment.CX500DistinguishedName.1"
    $name.Encode("CN=$commonName", 0)

    $key = new-object -com "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    $key.KeySpec = 1
    $key.Length = 1024
    $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $key.MachineContext = 1
    $key.Create()

    $serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
    $ekuoids.add($serverauthoid)
    $ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $cert.NotBefore = get-date
    $cert.NotAfter = $cert.NotBefore.AddDays($daysUntilExpiration)
    $cert.X509Extensions.Add($ekuext)
    $cert.Encode()

    $enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)
	$enrollment.CertificateFriendlyName = $friendlyName;
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")
}





