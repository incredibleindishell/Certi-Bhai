  param (
    [Parameter(Mandatory = $true, Position = 0)] [string]$subjectName,
    [Parameter(Mandatory = $true, Position = 1)] [string]$altName
) 
Write-Host ""
Write-Host "   ____            _   _    ____  _           _ "
Write-Host "  / ___|  ___ _ __| |_(_)  | __ )| |__   __ _(_)"
Write-Host " | |     / _ | '__| __| |  |  _ \| '_ \ / _ ` | |"
Write-Host " | |___ |  __| |  | |_| |  | |_) | | | | (_| | |"
Write-Host "  \____| \___|_|   \__|_|  |____/|_| |_|\__,_|_|"
Write-Host "                                            "
Write-Host "                               Because AD CS is a Pure Gold \m/  "
if (-not $subjectName -or -not $altName) {
    Write-Host "Missing required parameters. Usage: .\CSR_generate.ps1 -subjectName 'CN=administrator, CN=Users, DC=indishell, DC=lab' -altName 'administrator' "
    exit
}


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

$PrivateKeyBase64 = $PrivateKey.Export("PRIVATEBLOB") # 1 = XCN_CRYPT_STRING_BASE64

Write-Output "Base64 Private Key: `n$PrivateKeyBase64"
# Create a new certificate request object
$CertRequest = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
$CertRequest.InitializeFromPrivateKey(0x1, $PrivateKey, "")  # ContextUser

$AltNames = New-Object -ComObject X509Enrollment.CAlternativeNames
$AltNameobj = New-Object -ComObject X509Enrollment.CAlternativeName
$AltNameobj.InitializeFromString(0xb,$altName)  # UPN SAN
$AltNames.Add($AltNameobj)



$SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
$SAN.InitializeEncode($AltNames)
$CertRequest.X509Extensions.Add($SAN)

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

# Set Application Policies
$OIDs = New-Object -ComObject X509Enrollment.CObjectIds
$Policies = New-Object -ComObject X509Enrollment.CCertificatePolicies
    
$OID = New-Object -ComObject X509Enrollment.CObjectId
$Policy = New-Object -ComObject X509Enrollment.CCertificatePolicy
$OID.InitializeFromValue("1.3.6.1.5.5.7.3.2")
$Policy.Initialize($OID)
$OIDs.Add($OID)
$Policies.Add($Policy)


$cEKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
$cMSAppId = New-Object -ComObject X509Enrollment.CX509ExtensionMSApplicationPolicies

$cEKU.InitializeEncode($OIDs)
$cMSAppId.InitializeEncode($Policies)

$CertRequest.X509Extensions.Add($cMSAppId)

# Create the enrollment object
$Enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
$Enrollment.InitializeFromRequest($CertRequest)

# Encode the request in-memory
$CSR = $Enrollment.CreateRequest(0)
Write-Host "Certificate request generated in memory."
$CSR
