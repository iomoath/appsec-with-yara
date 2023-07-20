## Appsec With YARA

This repository houses a collection of YARA rules designed to assist with secure code reviews. Currently, there are two specific sets of YARA rules which is specific for PHP and C# languages.

Keep in mind that the results require manual review. These rules are not designed to scan for actual vulnerabilities, instead they assist in code analysis, finding interesting pieces of code.


## Available Rules

### PHP Ruleset
- php_file_inclusion_detection
- php_xss_detection
- php_user_input_sql_operations
- php_user_input_file_operations
- php_insecure_deserialization
- php_command_execution_functions
- php_risky_function_usage
- php_deprecated_function_usage
- php_user_input_detection

### C# Ruleset
- csharp_file_inclusion_detection
- csharp_xss_detection
- csharp_user_input_sql_operations
- csharp_user_input_file_operations
- csharp_command_execution_detection
- csharp_user_input_detection


## YARA Scanner
I personally use the YARA scanner tool [yara-scanner](https://github.com/iomoath/yara-scanner) for its simplicity and the HTML scan reports it provides. Alternatively, the [Loki](https://github.com/Neo23x0/Loki) scanner is also a good option.


## Interesting Reads
[Hunting 0days with YARA Rules](https://c99.sh/hunting-0days-with-yara-rules/)


## Contributing
Your contributions and improvements are valuable and welcome. Please feel free to submit your rules :)