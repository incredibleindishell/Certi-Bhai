# --==[[ Certi Bhai - ESC3 Exploitation ]]==--
This PowerShell-based script is designed to demonstrate the security implications of a misconfigured Windows Active Directory Certificate Services (AD CS) template. 

It is run using a Domain user or machine account that has Enroll permission on an affected template. 
The script accepts the following inputs: 
```
templateName
target_user
domain
pfxPass
```
Using those parameters, the script creates a certificate signing request (CSR) and submits it to the AD CS service to request a certificate from the specified certificate template which has `Certificate Request Agent` EKU configured in it. 
When the certificate (having `Certificate Request Agent` EKU) is issued by AD CS, the script request another certificate on behalf of a high privileged Domain user (such as Domain admin) by presenting the certificate issued in step 1.  
Whene everything goes fine, script prints a command compatible with `Rubeus` and makes the issued certificate of targeted domain user available in PFX format( in base64-encoded format) in the `/certificate` parameter of that command.

## Usage
We can either simply provide the parameter values directly to this PowerShell script, like this:

```
. .\esc3_working.ps1 -templateName 'agent' -target_user 'administrator' -domain queen -pfxPass 'password'
```
Or just load the script and provide inputs one by one:

![ESC3](https://raw.githubusercontent.com/incredibleindishell/Certi-Bhai/refs/heads/main/ESC3/ESC3_working.png)
