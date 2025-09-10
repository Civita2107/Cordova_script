import os
import json
import xml.etree.ElementTree as ET
import subprocess
import sys
import shutil
import re

REPORT = {}

def run_apktool(apk_file, output_dir="apk_decoded"):
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)  
    try:
        subprocess.run(["apktool", "d", apk_file, "-o", output_dir, "-f"], check=True)
        return output_dir
    except Exception as e:
        print(f"[!] Apktool failed: {e}")
        sys.exit(1)

def check_manifest(decoded_dir):
    manifest_file = os.path.join(decoded_dir, "AndroidManifest.xml")
    try:
        tree = ET.parse(manifest_file)
        root = tree.getroot()
        permissions = [
            p.attrib.get("{http://schemas.android.com/apk/res/android}name")
            for p in root.findall("uses-permission")
        ]
        REPORT["internet_permission"] = "android.permission.INTERNET" in permissions
    except Exception as e:
        REPORT["internet_permission"] = f"Error parsing manifest: {e}"

def check_config(decoded_dir):
    config_file = os.path.join(decoded_dir, "res/xml/config.xml")
    if not os.path.exists(config_file):
        REPORT["allow_navigation"] = "config.xml not found"
        REPORT["allow_intent"] = "config.xml not found"
        return
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            content = f.read()
            REPORT["allow_navigation"] = '<allow-navigation href="http://*"' in content
            REPORT["allow_intent"] = '<allow-intent href="http://*"' in content
    except Exception as e:
        REPORT["allow_navigation"] = f"Error: {e}"
        REPORT["allow_intent"] = f"Error: {e}"

def check_access_origin(decoded_dir):
    """Check for <access origin> tags in config.xml"""
    config_file = os.path.join(decoded_dir, "res/xml/config.xml")
    if not os.path.exists(config_file):
        REPORT["access_origin"] = "config.xml not found"
        REPORT["access_origin_details"] = []
        REPORT["wildcard_access_origin"] = False
        REPORT["permissive_access_origin"] = False
        return
    
    try:
        tree = ET.parse(config_file)
        root = tree.getroot()
        
        # Find all access tags
        access_tags = root.findall("access")
        
        if not access_tags:
            REPORT["access_origin"] = "No access origin tags found"
            REPORT["access_origin_details"] = []
            REPORT["wildcard_access_origin"] = False
            REPORT["permissive_access_origin"] = False
        else:
            access_origins = []
            for access in access_tags:
                origin = access.attrib.get("origin", "")
                launch_external = access.attrib.get("launch-external", "")
                
                access_info = {
                    "origin": origin,
                    "launch_external": launch_external if launch_external else None
                }
                access_origins.append(access_info)
            
            REPORT["access_origin"] = f"{len(access_origins)} access origin tag(s) found"
            REPORT["access_origin_details"] = access_origins
            
            # Check for wildcard origins (security concern)
            wildcard_origins = [acc for acc in access_origins if acc["origin"] == "*"]
            REPORT["wildcard_access_origin"] = len(wildcard_origins) > 0
            
            # Check for permissive access origins (alternative to CSP missing)
            # Consider permissive if wildcard or multiple broad domains are allowed
            permissive_patterns = ["*", "http://*", "https://*", "file://*"]
            permissive_origins = [acc for acc in access_origins 
                                if acc["origin"] in permissive_patterns or 
                                   acc["origin"].startswith("http://") or 
                                   acc["origin"].startswith("https://")]
            REPORT["permissive_access_origin"] = len(permissive_origins) > 0
            
    except Exception as e:
        REPORT["access_origin"] = f"Error parsing config.xml: {e}"
        REPORT["access_origin_details"] = []
        REPORT["wildcard_access_origin"] = False
        REPORT["permissive_access_origin"] = False

def check_plugin_file(decoded_dir):
    plugin_path = os.path.join(decoded_dir, "assets/www/plugins/cordova-plugin-file")
    REPORT["cordova_plugin_file"] = os.path.isdir(plugin_path)

def check_index_csp(decoded_dir):
    index_file = os.path.join(decoded_dir, "assets/www/index.html")
    if not os.path.exists(index_file):
        REPORT["index_csp"] = "index.html not found"
        REPORT["resolveLocalFileSystemURL_index"] = "index.html not found"
        return
    try:
        with open(index_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            # strip HTML comments
            content_no_comments = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)

            # CSP check
            if re.search(r'<meta[^>]+Content-Security-Policy', content_no_comments, re.IGNORECASE):
                REPORT["index_csp"] = "CSP present"
            else:
                REPORT["index_csp"] = "CSP missing"

            # resolveLocalFileSystemURL check
            REPORT["resolveLocalFileSystemURL_index"] = "resolveLocalFileSystemURL" in content_no_comments
    except Exception as e:
        REPORT["index_csp"] = f"Error reading index.html: {e}"
        REPORT["resolveLocalFileSystemURL_index"] = f"Error reading index.html: {e}"


def check_js_usage(decoded_dir):
    suspicious_files = []
    js_path = os.path.join(decoded_dir, "assets/www/js")
    if not os.path.isdir(js_path):
        REPORT["resolveLocalFileSystemURL_js"] = "js folder not found"
        return

    for root, _, files in os.walk(js_path):
        for file in files:
            if file.endswith(".js"):
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        if "resolveLocalFileSystemURL" in content:
                            suspicious_files.append(path)
                except:
                    pass
    REPORT["resolveLocalFileSystemURL_js"] = suspicious_files if suspicious_files else False

def evaluate_vulnerabilities():
    vulns = []

    csp_missing = REPORT.get("index_csp") == "CSP missing"
    internet = REPORT.get("internet_permission") is True
    cordova_plugin_file = REPORT.get("cordova_plugin_file") is True
    allow_navigation = REPORT.get("allow_navigation") is True
    resolve_in_index = REPORT.get("resolveLocalFileSystemURL_index") is True
    resolve_in_js = REPORT.get("resolveLocalFileSystemURL_js") not in [False, "js folder not found"]
    wildcard_access = REPORT.get("wildcard_access_origin") is True
    permissive_access = REPORT.get("permissive_access_origin") is True

    resolve_used = resolve_in_index or resolve_in_js
    
    # Security weakness indicator: CSP missing OR permissive access origin
    security_weakness = csp_missing or permissive_access

    # 1. External Script Injection → File Plugin API
    if security_weakness and internet and cordova_plugin_file and resolve_used:
        reason = []
        if csp_missing:
            reason.append("CSP missing")
        if permissive_access:
            reason.append("permissive access origin configuration")
        vulns.append(f"External Script Injection accessing the Cordova File Plugin API (due to: {', '.join(reason)})")

    # 2. External Script Injection → HTML files
    if security_weakness and internet:
        reason = []
        if csp_missing:
            reason.append("CSP missing")
        if permissive_access:
            reason.append("permissive access origin configuration")
        vulns.append(f"External Script Injection accessing the application HTML files (due to: {', '.join(reason)})")

    # 3. Same-Origin Iframe → File Plugin API
    if security_weakness and internet and cordova_plugin_file and resolve_used and allow_navigation:
        reason = []
        if csp_missing:
            reason.append("CSP missing")
        if permissive_access:
            reason.append("permissive access origin configuration")
        vulns.append(f"Same-Origin Iframe loading of malicious files accessing the Cordova File Plugin API (due to: {', '.join(reason)})")

    # 4. Same-Origin Iframe → HTML files
    if security_weakness and internet and allow_navigation:
        reason = []
        if csp_missing:
            reason.append("CSP missing")
        if permissive_access:
            reason.append("permissive access origin configuration")
        vulns.append(f"Same-Origin Iframe loading of malicious files accessing the application HTML files (due to: {', '.join(reason)})")

    # 5. Wildcard access origin vulnerability (specific case)
    if wildcard_access:
        vulns.append("Wildcard access origin (*) allows unrestricted external access")

    # Add summary of security control status
    security_summary = {
        "csp_status": REPORT.get("index_csp", "unknown"),
        "access_origin_status": REPORT.get("access_origin", "unknown"),
        "has_permissive_access": permissive_access,
        "has_wildcard_access": wildcard_access,
        "security_controls_adequate": not security_weakness
    }
    REPORT["security_analysis_summary"] = security_summary

    REPORT["vulnerability_verdicts"] = vulns if vulns else ["No vulnerabilities detected"]

def main():
    if len(sys.argv) != 2:
        print("Usage: python cordova_static_analysis.py <app.apk>")
        sys.exit(1)

    apk_file = sys.argv[1]
    decoded_dir = run_apktool(apk_file)

    check_manifest(decoded_dir)
    check_config(decoded_dir)
    check_access_origin(decoded_dir)
    check_plugin_file(decoded_dir)
    check_index_csp(decoded_dir)
    check_js_usage(decoded_dir)

    evaluate_vulnerabilities()

    with open("static_analysis_report.json", "w", encoding="utf-8") as out:
        json.dump(REPORT, out, indent=4)

    print("[+] Analysis complete. Results saved to static_analysis_report.json")
    print(json.dumps(REPORT, indent=4))

if __name__ == "__main__":
    main()