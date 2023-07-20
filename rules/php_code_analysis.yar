rule php_file_inclusion_detection {
  meta:
    description = "Detects potential LFI/RFI vulnerabilities in PHP scripts"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"

  strings:
    $p1 = "<?"

    $i1 = "$_GET["
    $i2 = "$_POST["
    $i3 = "$_REQUEST["
    $i4 = "$_COOKIE["

    $f1 = "include(" nocase
    $f2 = "include_once(" nocase
    $f3 = "require(" nocase
    $f4 = "require_once(" nocase

  condition:
    filesize < 2MB and
    $p1 at 0 and 
    any of ($i*) and
    any of ($f*)
}


rule php_xss_detection {
  meta:
    description = "Detects potential XSS vulnerabilities in PHP scripts"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"

  strings:
    $p1 = "<?"

    $i1 = "$_GET["
    $i2 = "$_POST["
    $i3 = "$_REQUEST["

    $o1 = "echo " nocase
    $o2 = "print " nocase
    $o3 = "print_r(" nocase

    $x1 = "htmlentities(" nocase
    $x2 = "htmlspecialchars(" nocase

  condition:
    filesize < 2MB and
    $p1 at 0 and 
    any of ($i*) and 
    any of ($o*)
    and not any of ($x*)
}



rule php_user_input_sql_operations_v1 {
  meta:
    description = "Detects potential SQL injection vulnerabilities in PHP scripts"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"
  strings:
    $p1 = "<?"

    $i1 = "$_GET["
    $i2 = "$_POST["
    $i3 = "$_REQUEST["
    $i4 = "$_COOKIE["
    $i5 = "$_FILES["

    $f1 = "mysql_query(" nocase
    $f2 = "mysqli_query(" nocase
    $f3 = "mssql_query(" nocase
    $f4 = "sqlsrv_query(" nocase
    $f5 = "pdo->query(" nocase
    $f6 = "pdo->prepare(" nocase
    $f7 = "pg_query(" nocase

    $s1 = "SELECT " nocase
    $s2 = "UPDATE " nocase
    $s3 = "DELETE " nocase
    $s4 = "INSERT " nocase

  condition:
    filesize < 2MB and
    $p1 at 0 and 
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



rule php_user_input_sql_operations_v2
{
  meta:
    description = "Detects potential SQL injection vulnerabilities in PHP scripts"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"
  strings:
    $p = "<?" nocase

    $i1 = "$_GET["
    $i2 = "$_POST["
    
    $f1 = "mysql_query(" nocase
    $f2 = "mysqli_query(" nocase
    $f3 = "mssql_query(" nocase
    $f4 = "sqlsrv_query(" nocase
    $f5 = "pdo->query(" nocase
    $f6 = "pdo->prepare(" nocase
    $f7 = "pg_query(" nocase

  condition:
    filesize < 2MB and
    $p at 0 and 
    any of ($i*) and 
    any of ($f*)
}


rule php_user_input_file_operations
{
  meta:
    description = "Detects potential file upload functionality in PHP scripts"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"
  strings:
    $p1 = "<?"

    $i1 = "$_POST[" 
    $i2 = "$_FILES["
    $i3 = "php://input" nocase

    $f1 = "move_uploaded_file(" nocase
    $f2 = "file_put_contents(" nocase
    $f3 = "fwrite(" nocase
    $f4 = "copy(" nocase
    $f5 = "rename(" nocase
  condition:
    filesize < 2MB and
    $p1 at 0 and 
    (any of ($i*) and any of ($f*))
}


rule php_user_input_file_operations_v2 {
  meta:
    description = "Detects potential file upload functionality in PHP scripts"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"

  strings:
    $p1 = "<?"

    $i1 = "$_FILES["

    $f1 = ".['type']" nocase // mime-type
    $f2 = ".['name']" nocase // original file name
    $f3 = ".['tmp_name']" nocase // temporary file name
  condition:
    filesize < 2MB and
    $p1 at 0 and 
    (any of ($i*) and any of ($f*))
}




rule php_insecure_deserialization {
  meta:
    description = "Detects potential insecure deserialization vulnerabilities in PHP scripts"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"

  strings:
    $p1 = "<?"

    // https://www.php.net/manual/en/function.unserialize.php
    // https://www.php.net/manual/en/function.yaml-parse.php
    // https://notsosecure.com/remote-code-execution-php-unserialize
    // https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection
    // https://www.invicti.com/blog/web-security/untrusted-data-unserialize-php/

    /** // Insecure PHP deserialization
     if (isset($_GET['payload'])) {
        $data = unserialize($_GET['payload']);
        echo $data;
    } **/
  
  /** // Insecure PHP YAML parsing
  if (isset($_GET['payload'])) {
      $data = yaml_parse($_GET['payload']);
      print_r($data);
  } **/
  
    $f1 = "unserialize(" nocase
    $f2 = "yaml_parse(" nocase

  condition:
    filesize < 2MB and
    $p1 at 0 and 
    any of ($f*)
}



rule php_command_execution_functions
{
  meta:
    description = "Detects usage of PHP command execution functions"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"
  strings:
    $p1 = "<?"

    $f1 = "exec(" nocase
    $f2 = "passthru(" nocase
    $f3 = "system(" nocase
    $f4 = "shell_exec(" nocase
    $f5 = "popen(" nocase
    $f6 = "proc_open(" nocase
    $f7 = "pcntl_exec(" nocase
  condition:
    filesize < 2MB and
    $p1 at 0 and any of ($f*)
}


rule php_risky_function_usage {
  meta:
    description = "Detects usage of potentially risky PHP functions"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"

  strings:
    $p = "<?"

    $r1 = "eval(" nocase
    $r2 = "exec(" nocase
    $r3 = "system(" nocase
    $r4 = "shell_exec(" nocase
    $r5 = "passthru(" nocase
    $r6 = "popen(" nocase
    $r7 = "proc_open(" nocase
    $r8 = "assert(" nocase
    $r9 = "create_function(" nocase

  condition:
    filesize < 2MB and
    $p at 0 and 
    any of ($r*)
}


rule php_deprecated_function_usage {
  meta:
    description = "Detects usage of deprecated PHP functions"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"

  strings:
    $p = "<?"

    $d1 = "mysql_query(" nocase
    $d2 = "ereg(" nocase
    $d3 = "ereg_replace(" nocase
    $d4 = "eregi(" nocase
    $d5 = "set_magic_quotes_runtime(" nocase
    $d6 = "magic_quotes_runtime(" nocase
    $d7 = "session_register(" nocase
    $d8 = "session_unregister(" nocase
    $d9 = "session_is_registered(" nocase

  condition:
    filesize < 2MB and
    $p at 0 and 
    any of ($d*)
}


rule php_user_input_detection {
  meta:
    description = "Detects potential user input in PHP scripts"
    author      = "Moath Maharmeh"
    date        = "2023-07-20"
    filetype    = "php"
  strings:
    $p1 = "<?"

    $i1 = "$_GET["
    $i2 = "$_POST["
    $i3 = "$_REQUEST["
    $i4 = "$_COOKIE["
    $i5 = "$_FILES["

  condition:
    filesize < 2MB and
    $p1 at 0 and 
    any of ($i*)
}