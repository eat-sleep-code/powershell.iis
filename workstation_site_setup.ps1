

# ========================================================================================================
# SEE END OF FILE FOR EXAMPLE USAGE AND COMMAND THAT WILL BE EXECUTED!
# ========================================================================================================














Function Process-Site-Definitions-Url([string]$xmlUrl, [boolean]$overwrite = $false, [boolean]$removeSite = $false)
{
    # GETS CONTENTS OF WEB-HOSTED XML FILE, COPIES THEM TO A TEMPORARY FILE, PROCESSES FILE USING Process-Site-Definitions, AND THEN REMOVES THE TEMPORARY FILE 
    Import-Module WebAdministration;
    [DateTime]$date = Get-Date; # GET CURRENT DATE
    [string]$xmlPath = "$env:TEMP\site_definitions_" + $date.ToString("yyyyMMdd") + ".xml"; # SET THE PATH FOR THE LOCAL COPY OF THE XML FILE, IN THE USERS "TEMP" FOLDER
    $web = New-Object Net.WebClient; # CREATE THE WEB CLIENT
    # DO WE NEED TO ADD PROXY HANDLING HERE?
    $web.DownloadFile($xmlUrl, $xmlPath); # DOWNLOAD THE WEB-BASED XML FILE INTO THE USERS "TEMP FOLDER"
    Process-Site-Definitions -xmlFilePath $xmlPath -overwrite $overwrite -removeSite $removeSite; # PROCESS THE LOCAL COPY OF THE XML FILE 
    Remove-Item -Path $xmlPath; # REMOVE THE LOCAL COPY OF THE XML FILE
};





Function Process-Site-Definitions([string]$xmlFilePath = "site_definitions.xml", [boolean]$overwrite = $false, [boolean]$removeSite = $false)
{
    # GETS CONTENTS OF LOCAL XML FILE, CALLS New-Site, AND THEN SETS UP VIRTUAL DIRECTORIES (WHERE APPLICABLE)
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
			[string]$basePath = $site.basePath; # USED FOR LOGGING
            [int]$siteCount = (Get-Website | Where-Object {$_.name -eq $site.siteName}).count;
            if (($overwrite -eq $False) -and ($siteCount -gt 0))
            {
                [string]$siteName = $site.siteName;
                Log-Text "Site Already Exists (Skipping Creation): $siteName";
            }
            else
            {
                New-Site -basePath $site.basePath -siteName $site.siteName -siteFolder $site.siteFolder -hostHeader $site.hostHeader -port $site.port -ipAddress $site.ipAddress -netVersion $site.netVersion -enable32Bit ([System.Convert]::ToBoolean($site.enable32bit)) -classicPipelineMode ([System.Convert]::ToBoolean($site.classicPipelineMode));
                if ($site.certificate -ne "")
                {
                    Add-CertificateBinding -certificateSubject $site.certificate -ipAddress $site.ipAddress -port $site.port;
                }
                # CREATE VIRTUAL DIRECTORIES
                foreach ($directory in $site.virtualDirectories.directory)
                {
                    [boolean]$pathExists=Test-Path $directory.path;
                    if ($pathExists -eq $False)
                    {
                        [string]$name = $directory.name;
                        Log-Text "Creating Folder For Virtual Directory: $name";
                        New-Item $directory.path -type directory -Verbose | Log-Action;   
                    }
                    New-WebVirtualDirectory -Site $site.siteName -PhysicalPath $directory.path -Name $directory.name -Force; 
                }

                # CREATE ADDITIONAL BINDINGS
                foreach ($binding in $site.additionalBindings.binding)
                {
                    [string]$hostHeader = $binding.hostHeader;
                    [string]$port = $binding.port;
                    Log-Text "Creating Binding For Host Header: $hostHeader :$port";
                    New-WebBinding -Name $site.siteName -Protocol $binding.protocol -HostHeader $binding.hostHeader -Port $binding.port -ipAddress $binding.ipAddress -Verbose | Log-Action;
                    if ($binding.certificate -ne "")
                    {
                        Add-CertificateBinding -certificateSubject $binding.certificate -ipAddress $binding.ipAddress -port $binding.port;
                    }
                }
            }
        }
    }
};





Function New-Site([string]$basePath = "C:\InetPub\wwwroot\", [string]$siteName, [string]$siteFolder, [string]$hostHeader, [string]$ipAddress = "*", [int]$port = 80, [string]$netVersion = "4.0", [boolean]$enable32Bit = $false, [boolean]$classicPipelineMode = $false)
{      
    # CREATES FOLDERS, APPLICATION POOLS, WEB SITES, BINDINGS, ETC.
    Import-Module WebAdministration;
    
    # IF WEBSITE FOLDER DOES NOT EXIST, CREATE IT.
    [boolean]$pathExists=Test-Path $basePath$siteFolder;
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
        Log-Text "Creating Website: $siteName :$port";
        New-Website -Name $siteName -ApplicationPool "ASP.NET 1.1" -ipAddress $ipAddress -HostHeader $hostHeader -PhysicalPath $basePath$siteFolder -Force -Port $port -Verbose | Log-Action; # CREATE THE SITE
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
        Log-Text "Creating Website: $siteName :$port"; 
        New-Website -Name $siteName -ApplicationPool $siteName -ipAddress $ipAddress -HostHeader $hostHeader -PhysicalPath $basePath$siteFolder -Port $port  -Force -Verbose | Log-Action; # CREATE THE SITE
    }
};





Function Remove-Site([string]$basePath = "C:\InetPub\wwwroot\", [string]$siteName, [string]$siteFolder, [string]$hostHeader, [string]$netVersion = "4.0", [boolean]$removeFiles = $false)
{      
    # REMOVES A WEB SITE, EMPTY APPLICATION POOLS, AND EMPTY FOLDERS
    Import-Module WebAdministration;
    
    # REMOVE WEBSITE
    Try
    {
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
    }
    Catch
    {
        Log-Text "Files For $siteName Not Found, Skipping";
    }

    if ($removeFiles -eq $True)
    {
        #IF SPECIFIED FOLDER EXISTS, REMOVE IT
        [boolean]$pathExists=Test-Path $basePath$siteFolder;
        if ($pathExists -eq $True)
        {
            [string]$parentFolderPath = Split-Path $basePath$siteFolder -Parent;
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
    [DateTime]$date = Get-Date; # GET CURRENT DATE
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
};





Function Log-Text([string]$text, [string]$logBasePath = "")
{
    
    [DateTime]$date = Get-Date;
    [string]$logPath = $basePath + $date.ToString("yyyyMMdd") + ".log";
    if ($logBasePath -ne "")
    {
        $logPath = $logBasePath + $date.ToString("yyyyMMdd") + ".log";
    }
    [string]$currentTime = $date.ToString("hh:mm:ss tt");
    Add-Content $logPath "`n#$currentTime`t$text`r";
    Add-Content $logPath "`n#==============================================================================`r";
};





Function Log-Action()
{
    [DateTime]$date = Get-Date;
    $logPath = $basePath + $date.ToString("yyyyMMdd") + ".log";
    Out-File "$logPath" -encoding ASCII -Append -NoClobber;
};





Function Add-SelfSignedCertificate ([string]$commonName = "", [string]$friendlyName = "", [int]$daysUntilExpiration = 365)
{
    if ($commonName -eq "")
    {
        $commonName = [string]::Format('{0}.{1}', $env:computername, $env:userdnsdomain)
    }
    $startDate = [DateTime]::Now
    $expirationDate = $startDate.AddDays($daysUntilExpiration)

	# CREATE SUBJECT FIELD X.500 FORMAT
	$subjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
	$subjectDN.Encode("CN=$commonName", 0x0)
	
	# ADD CERTIFICATE KEY USAGE STATEMENTS
	$OIDs = New-Object -ComObject X509Enrollment.CObjectIDs
	
	# DEFINE SERVER AUTHENTICATION ENHANCED KEY USAGE (OID = 1.3.6.1.5.5.7.3.1)
	$OID = New-Object -ComObject X509Enrollment.CObjectID
	$OID.InitializeFromValue("1.3.6.1.5.5.7.3.1")
	$OIDs.Add($OID)

	# DEFINE CLIENT AUTHENTICATION ENHANCED KEY USAGE (OID = 1.3.6.1.5.5.7.3.2) 
	$OID = New-Object -ComObject X509Enrollment.CObjectID
	$OID.InitializeFromValue("1.3.6.1.5.5.7.3.2")
	$OIDs.Add($OID)
	
	# DEFINE SMARTCARD AUTHENTICATION ENHANCED KEY USAGE (OID = 1.3.6.1.4.1.311.20.2.2) 
	$OID = New-Object -ComObject X509Enrollment.CObjectID
	$OID.InitializeFromValue("1.3.6.1.4.1.311.20.2.2")
	$OIDs.Add($OID)

	# DEFINE CODE-SIGNING AUTHENTICATION ENHANCED KEY USAGE (OID = 1.3.6.1.5.5.7.3.3)
	$OID = New-Object -ComObject X509Enrollment.CObjectID
	$OID.InitializeFromValue("1.3.6.1.5.5.7.3.3")
	$OIDs.Add($OID)
	
	# CREATE ENHANCED KEY USAGE EXTENSION
	$EKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
	$EKU.InitializeEncode($OIDs)
	
	# GENERATE PRIVATE KEY
	$privateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
	$privateKey.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
	$privateKey.KeySpec = 0x1
	$privateKey.Length = 2048
	# SET SECURITY DESCRIPTOR
	$privateKey.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
	# KEY WILL BE STORED IN LOCAL MACHINE CONTEXT
	$privateKey.MachineContext = 0x1
	# EXPORT WILL BE ALLOWED
	$privateKey.ExportPolicy = 0x1
	$privateKey.Create()
	
	# CREATE CERTIFICATE REQUEST TEMPLATE
	$cert = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
	$cert.InitializeFromPrivateKey(0x2,$PrivateKey,"")
	$cert.Subject = $subjectDN
	$cert.Issuer = $cert.Subject
	$cert.NotBefore = $startDate
	$cert.NotAfter = $expirationDate
	$cert.X509Extensions.Add($EKU)
	$Cert.Encode()
	
	# PROCESS REQUEST AND BUILD END CERTIFICATE
	$request = New-Object -ComObject X509Enrollment.CX509enrollment
	# PROCESS REQUEST
	$request.InitializeFromRequest($Cert)
    # SET FRIENDLY NAME
    if ($friendlyName -ne "")
    {
        $request.CertificateFriendlyName = $friendlyName;
    }
	# RETRIEVE CERTIFICATE ENCODED IN BASE64
	$endCert = $request.CreateRequest(0x1)
	# INSTALL CERTIFICATE IN USER STORE
	$request.InstallResponse(0x2,$endCert,0x1,"")
	
	
	# CONVERT BASE64 STRING TO STRING ARRAY
 	[Byte[]]$bytes = [System.Convert]::FromBase64String($endCert)
	foreach ($container in "Root", "TrustedPublisher") 
	{
		# OPEN TRUSTED ROOT CERTIFICATE AUTHORITIES AND TRUSTED PUBLISHERS CONTAINERS AND ADD CERTIFICATE
		$x509store = New-Object Security.Cryptography.X509Certificates.X509Store $container, "LocalMachine"
		$x509store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
		$x509store.Add([Security.Cryptography.X509Certificates.X509Certificate2]$bytes)
		# CLOSE STORE WHEN OPERATION COMPLETE
		$x509store.Close()
	}		
};






function Remove-SelfSignedCertificate([string]$certificateSubject = "CN=*")
{
    # REMOVES ALL INSTANCES OF A CERTIFICATE ANYWHERE ON TREE, USE WITH CAUTION!
    $thumbprints = (Get-Item Cert:\*\*\* | Where-Object {$_.Subject -like "$certificateSubject*"} | Select-Object).Thumbprint;
    foreach ($thumbprint in $thumbprints)
    {
        Remove-Item -Path Cert:\LocalMachine\*\$thumbprint -Recurse -Force;
        Remove-Item -Path Cert:\CurrentUser\*\$thumbprint -Recurse -Force;
    }
};





function Add-CertificateBinding([string]$certificateSubject = "CN=*", [string]$ipAddress = "0.0.0.0", [int]$port = 443)
{
    Import-Module WebAdministration;
    Try
    {
        if ($ipAddress -eq "*")
        {
            $ipAddress = "0.0.0.0";
        }
        $thumbprint = (Get-ChildItem cert:\LocalMachine\TrustedPublisher | where-object { $_.Subject -like "$certificateSubject*" } | Select-Object -First 1).Thumbprint;
        if ($thumbprint -eq "")
        {
            Add-SelfSignedCertificate -commonName $certificateSubject -friendlyName $certificateSubject -daysUntilExpiration 365
            $thumbprint = (Get-ChildItem cert:\LocalMachine\TrustedPublisher | where-object { $_.Subject -like "$certificateSubject*" } | Select-Object -First 1).Thumbprint;
        }
        Push-Location IIS:\SslBindings;
        Get-Item Cert:\LocalMachine\TrustedPublisher\$thumbprint | New-Item $ipAddress!$port;
        Pop-Location;
    }
    Catch
    {
        Log-Text "Error Adding Certificate Binding: $certificateSubject";
    }
};





function Remove-CertificateBinding([string]$ipAddress, [int]$port = 443)
{
    Import-Module WebAdministration;
    if ($ipAddress -eq "*")
    {
        $ipAddress = "0.0.0.0";
    }
    Push-Location IIS:\SslBindings;
    Remove-Item $ipAddress!$port; 
    Pop-Location;
};






# === BEGIN EXAMPLE USAGE ==============================================================================
# 
# Process-Site-Definitions-Url -xmlUrl "http://127.0.0.1/xml/site_definitions.xml" -removeSite $true;
# Process-Site-Definitions -xmlFilePath "site_definitions.xml" -overwrite $false -removeSite $true;
# New-Site -basePath "C:\SRC\" -siteName "www.example.com" -siteFolder "example.com\www" -hostHeader "www.example.local";
# Remove-Site "C:\SRC\" -siteName "www.example.com" -siteFolder "example.com\www" -hostHeader "www.example.local" -removeFiles $true;
#
# Process-TFS-Definitions-Url -xmlUrl "http://127.0.0.1/xml/tfs_definitions.xml";
# Process-TFS-Definitions "tfs_definitions.xml";
# Prepare-TFS -sourceLocation "$/path/to/server/files" -localPath "C:\SRC\EXAMPLE" -collection "http://127.0.0.1:8080/tfs";
#
# Add-SelfSignedCertificate -commonName "Self-Signed Certificate" -friendlyName "Self-Signed Certificate" -daysUntilExpiration 365
# Remove-SelfSignedCertificate -certificateSubject "CN=Self-Signed Certificate"; # KNOW WHAT YOU ARE DOING BEFORE YOU EXECUTE THIS LINE!
#
# === END EXAMPLE USAGE ==================================================================================
