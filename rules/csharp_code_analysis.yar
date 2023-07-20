rule csharp_file_inclusion_detection {
  meta:
    description = "Detects potential file inclusion vulnerabilities"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "cs"

  strings:
    $i1 = "Request[\""
    $i2 = "Request.Form[\""
    $i3 = "Request.QueryString[\""
    $i4 = "Request.Cookies[\""
    
    $f1 = "File.ReadAllText("
    $f2 = "File.ReadAllLines("
    $f3 = "Assembly.LoadFile("
    $f4 = "Assembly.LoadFrom("

  condition:
    filesize < 2MB and
    any of ($i*) and
    any of ($f*)
}

rule csharp_xss_detection {
  meta:
    description = "Detects potential XSS vulnerabilities"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "cs"

  strings:
    $i1 = "Request[\""
    $i2 = "Request.Form[\""
    $i3 = "Request.QueryString[\""

    $o1 = "Response.Write("
    $o2 = "Response.Output.Write("
    $o3 = "HtmlString("
    $o4 = "HtmlRaw("

    $x1 = "HttpUtility.HtmlEncode("
    $x2 = "HttpUtility.UrlEncode("

  condition:
    filesize < 2MB and
    any of ($i*) and 
    any of ($o*)
    and not any of ($x*)
}

rule csharp_user_input_sql_operations_v1 {
  meta:
    description = "Detects potential SQL injection vulnerabilities"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "cs"

  strings:
    $i1 = "Request[\""
    $i2 = "Request.Form[\""
    $i3 = "Request.QueryString[\""
    $i4 = "Request.Cookies[\""
    $i5 = "Request.Files[\""

    $f1 = "SqlCommand("
    $f2 = "SqlDataAdapter("
    $f3 = "OleDbCommand("
    $f4 = "OleDbDataAdapter("
    $f5 = "EntityCommand("
    $f6 = "EntityDataAdapter("
    $f7 = "SqlCeCommand("
    $f8 = "SqlCeDataAdapter("

    $s1 = "SELECT" nocase
    $s2 = "UPDATE" nocase
    $s3 = "DELETE" nocase
    $s4 = "INSERT" nocase

  condition:
    filesize < 2MB and
    any of ($i*) and 
    (
      (
        any of ($f*) and 
        (
          1 of ($s*)
        )
      )
    )
}

rule csharp_user_input_sql_operations_v2
{
  meta:
    description = "Detects potential SQL injection vulnerabilities in C# scripts"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "csharp"

  strings:
    $i1 = "Request.QueryString["
    $i2 = "Request.Form["

    $f1 = "SqlCommand("
    $f2 = "SqlDataAdapter("
    $f3 = "ExecuteNonQuery("
    $f4 = "ExecuteReader("
    $f5 = "ExecuteScalar("
    $f6 = "ExecuteXmlReader("
    $f7 = "ExecuteReader("
    $f8 = "SqlDataReader("

  condition:
    filesize < 2MB and
    any of ($i*) and 
    any of ($f*)
}


rule csharp_user_input_file_operations {
  meta:
    description = "Detects potential file upload functionality"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "cs"

  strings:
    $i1 = "Request.Files[\""

    $f1 = "SaveAs("
    $f2 = "File.WriteAllBytes("
    $f3 = "File.WriteAllLines("
    $f4 = "File.Move("
    $f5 = "File.Copy("

  condition:
    filesize < 2MB and
    any of ($i*) and any of ($f*)
}


rule csharp_command_execution_detection {
  meta:
    description = "Detects usage of .NET command execution functions"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "cs"

  strings:
    $f1 = "Process.Start("
    $f2 = "Process.StartInfo.FileName"
    $f3 = "Process.StartInfo.Arguments"

  condition:
    filesize < 2MB and any of ($f*)
}


rule csharp_user_input_detection {
  meta:
    description = "Detects potential user input"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "cs"

  strings:
    $i1 = "Request[\""
    $i2 = "Request.Form[\""
    $i3 = "Request.QueryString[\""
    $i4 = "Request.Cookies[\""
    $i5 = "Request.Files[\""

  condition:
    filesize < 2MB and
    any of ($i*)
}
