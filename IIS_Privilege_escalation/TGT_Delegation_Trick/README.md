# ASPX Webshell: Kerberos TGT Extraction via Fake Delegation Trick 

## Overview

This ASPX code is useful in scenarios where a compromised IIS web application is hosted on a domain-joined Windows machine and is running under the privileges of an **IIS virtual account**.

The code implements the technique used by [Rubeus](https://github.com/GhostPack/Rubeus) `tgtdeleg` command, adapted to run entirely from within an ASPX webshell.

It leverages Kerberos unconstrained delegation to extract the `KRBTGT` ticket of a machine account from within the compromised IIS web application.
When a web application runs under an **IIS virtual account** (e.g. `IIS APPPOOL\DefaultAppPool`), it inherits the Kerberos identity of the **machine account** (e.g. `WEBSERVER$`) of the host it runs on. If the target domain controller is configured for unconstrained delegation, which is the default for all domain controllers, this identity can be leveraged to extract a **forwarded TGT** for the machine account without any elevation of privilege.


## Full Attack Flow

```
1. Upload tgt_delegation.aspx to compromised IIS web root

2. Visit http://target/tgt_delegation..aspx
   └─ Copy AP-REQ (Base64)
   └─ Copy Session Key (Base64)

3. Run TGTExtractor.exe on attacker machine:
   TGtDelegation.exe /apreq:<AP-REQ> /session_key:<key> /output:base64

4. Use extracted TGT:
   └─ Windows: Rubeus.exe ptt /ticket:<base64_encoded_ticket>

```

---

## Part 1: ASPX Webshell (`tgt_delegation.aspx`)

#### What It Does

It is a single-file ASP.NET webshell that performs two oprations:

**Step 1: AP-REQ extraction via SSPI**

The page calls `AcquireCredentialsHandle` to obtain a Kerberos credential handle for the current process identity (the machine account), then calls `InitializeSecurityContext` with the `ISC_REQ_DELEGATE` flag set. This triggers Windows to build a GSS-API token containing a full Kerberos AP-REQ with a **forwarded KRBTGT embedded inside the authenticator**. The GSS token is captured from the output buffer and displayed as Base64.

**Step 2: Session key extraction via LSA**

The page connects to the Local Security Authority using `LsaConnectUntrusted`, looks up the Kerberos authentication package, then calls `LsaCallAuthenticationPackage` with `KerbRetrieveEncodedTicketMessage` to retrieve the session key for the service ticket from the Kerberos cache. The session key is required to decrypt the authenticator inside the AP-REQ in order to recover the forwarded TGT.

#### How It Works

```
Browser visits tgt_delegation.aspx
         ||
         \/
ResolveTargetSpn()
  ├─ ?target=<DC_hostname>  ->  append DNS suffix  ->  cifs/winbox2.domain.com
  └─ no ?target       ->  DNS resolve domain ->  auto-detect DC FQDN
         ||
         \/
AcquireCredentialsHandle("Kerberos", SECPKG_CRED_OUTBOUND)
  └─ Gets credential handle for WEBSERVER$ machine account
         ||
         \/
InitializeSecurityContext(ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ...)
  └─ Builds AP-REQ GSS token with forwarded TGT inside authenticator
  └─ Outputs: AP-REQ (Base64) -> displayed in textarea
         ||
         \/
LsaConnectUntrusted() + LsaLookupAuthenticationPackage("kerberos")
         ||
         \/
LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage,
                              KERB_RETRIEVE_TICKET_USE_CACHE_ONLY)
  └─ Retrieves session key from Kerberos ticket cache
  └─ Outputs: Session Key (Base64) + Encryption Type
```

#### Output

| Output | Description |
|-----------|-------------|
| **AP-REQ (Base64)** | GSS-API token containing the encrypted authenticator with the forwarded TGT inside |
| **Session Key (Base64)** | AES256/AES128/RC4 session key needed to decrypt the authenticator |
| **Encryption Type** | Etype used (e.g. AES256-CTS-HMAC-SHA1-96) |

#### Usage

Upload ASPX code to the comprommised IIS web application and visit it in a browser:

![](https://raw.githubusercontent.com/incredibleindishell/Certi-Bhai/refs/heads/main/IIS_Privilege_escalation/TGT_Delegation_Trick/aspx_code.png)

```
# Auto-detect DC
http://target/tgt_delegation.aspx

# Specify DC short hostname (domain suffix auto-appended)
http://target/tgt_delegation.aspx?target=<DC_hostname>
```

#### Requirements

- Web application must be running on a **domain-joined** machine
- Target DC must have **unconstrained delegation** enabled (default for all DCs)
- No local user account, web app runs as `IIS APPPOOL\DefaultAppPool`

---

## Part 2: TGT Extractor (`TGTDelegation.exe`)

#### What It Does

`TGTDelegation.exe` is a standalone Windows console tool that takes the `AP-REQ` and session key output from `tgt_delegation.aspx` and extracts the **Machine Account KRBTGT** from it. The output a valid `.kirbi` (KRB-CRED format) importable directly into `Rubeus`, `Mimikatz`, or any Kerberos tool, or alternatively a MIT `.ccache` file for use with Linux-based tools.

Note: The decryption logic is also borrowed from the [Rubeus](https://github.com/GhostPack/Rubeus) tool.

#### Usage

```
TGTDelegation.exe /apreq:<base64> /session_key:<base64> [/output:base64|ccache]
```

| Parameter | Description |
|-----------|-------------|
| `/apreq` | AP-REQ GSS token in Base64 (from `working.aspx`) |
| `/session_key` | Session key in Base64 (from `working.aspx`) |
| `/output` | Output format: `base64` (default) or `ccache` |

#### Examples

```cmd
# Default — outputs .kirbi as Base64
TGTDelegation.exe /apreq:YII... /session_key:NsD57FK...==

# ccache output for Linux tools
TGTDelegation.exe /apreq:YII... /session_key:NsD57FK...== /output:ccache
```
![](https://raw.githubusercontent.com/incredibleindishell/Certi-Bhai/refs/heads/main/IIS_Privilege_escalation/TGT_Delegation_Trick/TGT_extractor.png)

#### Using the Extracted TGT

**Windows — import with Rubeus:**
```cmd
Rubeus.exe ptt /ticket:<base64>
Rubeus.exe describe /ticket:<base64>
```

### Build

Requires .NET Framework 4.x. Must be compiled and run on a Windows machine (uses `cryptdll.dll`).

---

## Credits 

TGT Delegation Trick:  [Discovered by Benjamin Delpy](https://x.com/gentilkiwi/status/998219775485661184)  

AP-REQ and Session key extraction technique: [Rubeus](https://github.com/GhostPack/Rubeus)  

Kerberos decryption: [Rubeus](https://github.com/GhostPack/Rubeus)

## Thanks to:

My partners in crime: Karan Raheja and Manoj Chauhan

Supporter: Dominic Chell
