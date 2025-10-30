# --==[[ Certi Bhai - ESC1 Exploitation ]]==--

This PowerShell-based script is designed to demonstrate the security implications of a misconfigured Windows Active Directory Certificate Services (AD CS) template. 

It is run using a Domain user or machine account that has Enroll permission on an affected template. 
The script accepts the following inputs: 
```
subjectName
templateName
altName
pfxPass
```

Using those parameters, the tool creates a certificate signing request (CSR) and submits it to the AD CS service to request a certificate for the specified Active Directory user. 
When the certificate is issued by AD CS, the script prints a command compatible with `Rubeus` and makes the issued certificate available in PFX format( in base64-encoded format) in the `/certificate` parameter of that command.

## Usage
We can either simply provide the parameter values directly to this PowerShell script, like this:

```
. .\esc1.ps1 -subjectName 'CN=administrator, CN=Users, DC=indishell, DC=lab' -templateName 'vuln' -altName 'administrator' -pfxPass 'password'
```
Or just load the script and provide inputs one by one:

![ESC1](https://raw.githubusercontent.com/incredibleindishell/Certi-Bhai/refs/heads/main/ESC1/ESC1_ps1.png)


