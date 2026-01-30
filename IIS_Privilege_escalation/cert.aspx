<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Web" %>
<%@ Import Namespace="System.IO" %>


<script runat="server">
    protected void SubmitRequest(object sender, EventArgs e)
    {
        try
        {
            string caName = Request.Form["caName"];
            string templateName = Request.Form["templateName"];
            string csr = Request.Form["csr"];

            if (string.IsNullOrWhiteSpace(caName) || string.IsNullOrWhiteSpace(templateName) || string.IsNullOrWhiteSpace(csr))
            {
                result.InnerText = "All fields are required.";
                return;
            }

            // Create CX509Enrollment COM object dynamically
            Type enrollType = Type.GetTypeFromProgID("X509Enrollment.CX509Enrollment");
            dynamic enroll = Activator.CreateInstance(enrollType);

            // Initialize the request with CSR
            enroll.Initialize(2);  // ContextUser

            // Add request attributes (Template Name)
            Type objIdType = Type.GetTypeFromProgID("X509Enrollment.CObjectId");
            dynamic objId = Activator.CreateInstance(objIdType);
            objId.InitializeFromValue("1.3.6.1.4.1.311.20.2.2");  // OID for Certificate Template Name

            Type attrType = Type.GetTypeFromProgID("X509Enrollment.CX509Attribute");
            dynamic attr = Activator.CreateInstance(attrType);
            attr.Name = "CertificateTemplate";
            attr.RawData = System.Text.Encoding.ASCII.GetBytes(templateName);
            enroll.Request.Attributes.Add(attr);

            // Submit to the CA using RPC
            string cert = enroll.Enroll(csr, caName);
            result.InnerText = "Certificate issued successfully:\n\n" + cert;
        }
        catch (Exception ex)
        {
            result.InnerText = "Error: " + ex.Message;
        }
    }
</script>

<!DOCTYPE html>
<html>
<head>
    <title>AD CS Certificate Request</title>
</head>
<body>
    <h2>Submit CSR to AD CS RPC</h2>
    <form method="post" runat="server">
        <label>CA Name:</label>
        <input type="text" name="caName" required /><br /><br />

        <label>Template Name:</label>
        <input type="text" name="templateName" required /><br /><br />

        <label>CSR:</label><br />
        <textarea name="csr" rows="10" cols="50" required></textarea><br /><br />

        <button type="submit" onserverclick="SubmitRequest" runat="server">Submit</button>
    </form>

    <h3>Result:</h3>
    <pre id="result" runat="server"></pre>
</body>
</html>
