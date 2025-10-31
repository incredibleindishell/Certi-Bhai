# --==[[ Certi Bhai - ESC2 Exploitation ]]==--

This PowerShell-based script is designed to demonstrate the security implications of a misconfigured Windows Active Directory Certificate Services (AD CS) template. 

It is run using a Domain user or machine account that has Enroll permission on an affected template. 
The script accepts the following inputs: 
```
templateName
target_user
domain
pfxPass
```
Using those parameters, the script creates a certificate signing request (CSR) and submits it to the AD CS service to request a certificate from the specified certificate template which has `Any Purpose` EKU configured in it. 
When the certificate (having `Any Purpose` EKU) is issued by AD CS, the script request another certificate on behalf of a high privileged Domain user (such as Domain admin) by presenting the certificate issued in step 1.  
Whene everything goes fine, script prints a command compatible with `Rubeus` and makes the issued certificate of targeted domain user available in PFX format( in base64-encoded format) in the `/certificate` parameter of that command.

![ESC2](https://raw.githubusercontent.com/incredibleindishell/Certi-Bhai/refs/heads/main/ESC2/ESC2_working.png)
