# Cordova_script
This Python script performs a static security analysis of Android APKs built with **Apache Cordova**.
It automatically decodes the APK using **apktool**, inspects key configuration files, and flags potential security weaknesses that could lead to vulnerabilities.
## Requirements
- **Python 3.7+**
- **apktool** installed and available in your system **PATH**
## Features
The tool checks for the following:
- AndroidManifest.xml
  - Detects if the app requests the **INTERNET** permission
- config.xml
  - Flags **\<allow-navigation\>** with broad/wildcard patterns
  - Flags **\<allow-intent\>** with broad/wildcard patterns
  - Extracts **\<access origin\>** entries and highlights:
    - Wildcard origins (*)
    - Permissive patterns (**http://\***,**https://\***, **file://\***)
- Cordova File Plugin
  - Checks if **cordova-plugin-file** is included in the app
- index.html
  - Detects if a **Content Security Policy (CSP)** meta tag is present
  - Flags usage of **resolveLocalFileSystemURL**
- JavaScript files (**/assets/www/js/**)
  - Searches for resolveLocalFileSystemURL usage
## Vulnerabilities
- External Script Injection accessing the Cordova File Plugin API
- External Script Injection accessing the application HTML files
- Same-Origin Iframe loading of malicious files accessing the Cordova File Plugin API
- Same-Origin Iframe loading of malicious files accessing the application HTML files
## Usage
Run the script on a target APK:
```
python cordova_static_analysis.py <app.apk>
```
## Output
- Results are saved to static_analysis_report.json
- The script also prints a summary to the console
  - Example output snippet:
```
{
    "internet_permission": true,
    "allow_navigation": false,
    "allow_intent": false,
    "access_origin": "No access origin tags found",
    "access_origin_details": [],
    "wildcard_access_origin": false,
    "permissive_access_origin": false,
    "cordova_plugin_file": true,
    "index_csp": "CSP missing",
    "resolveLocalFileSystemURL_index": true,
    "resolveLocalFileSystemURL_js": false,
    "security_analysis_summary": {
        "csp_status": "CSP missing",
        "access_origin_status": "No access origin tags found",
        "has_permissive_access": false,
        "has_wildcard_access": false,
        "security_controls_adequate": false
    },
    "vulnerability_verdicts": [
        "External Script Injection accessing the Cordova File Plugin API (due to: CSP missing)",
        "External Script Injection accessing the application HTML files (due to: CSP missing)"
    ]
}
```
