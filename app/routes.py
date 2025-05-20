import os
import hashlib
import subprocess
import requests
import re
import base64
import xml.etree.ElementTree as ET
from flask import render_template, request, send_file
from weasyprint import HTML
from app import app

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ✅ Your real VirusTotal API key
VIRUSTOTAL_API_KEY = "e38c36b4b2fc8fa0e894def5bb2562f1f1dcb041b94ea35b93e80a0f63845039"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/{}"

@app.route("/", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        apk = request.files.get("apk")
        if apk and apk.filename.endswith(".apk"):
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], apk.filename)
            apk.save(filepath)

            print("APK upload received")
            print(f"Saved file: {filepath}")

            file_hash = sha256_checksum(filepath)
            vt_result = check_virustotal(file_hash)
            apk_analysis = analyze_apk(filepath)

            html_content = render_template(
                "report_template.html",
                sha256=file_hash,
                vt_result=vt_result,
                analysis=apk_analysis
            )
            report_path = os.path.join(REPORT_FOLDER, f"{file_hash}.pdf")
            HTML(string=html_content).write_pdf(report_path)

            return render_template(
                "upload.html",
                message="APK uploaded successfully!",
                sha256=file_hash,
                vt_result=vt_result,
                analysis=apk_analysis,
                report_link=f"/report/{file_hash}"
            )
        else:
            return render_template("upload.html", message="Please upload a valid .apk file.")
    return render_template("upload.html")

@app.route("/report/<hash>")
def report(hash):
    report_path = os.path.join(os.getcwd(), "reports", f"{hash}.pdf")
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=True)
    return "Report not found", 404

def sha256_checksum(filepath, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha256.update(block)
    return sha256.hexdigest()

def check_virustotal(file_hash):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = VIRUSTOTAL_URL.format(file_hash)
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return (
            f"Malicious: {stats.get('malicious', 0)}, "
            f"Suspicious: {stats.get('suspicious', 0)}, "
            f"Harmless: {stats.get('harmless', 0)}, "
            f"Undetected: {stats.get('undetected', 0)}"
        )
    elif response.status_code == 404:
        return "File not found in VirusTotal."
    else:
        return f"VirusTotal query failed (status code {response.status_code})."

def analyze_apk(filepath):
    output_dir = filepath + "_decoded"
    result = {
        "debuggable": False,
        "permissions": [],
        "uses_http": False,
        "hardcoded_secrets": [],
        "detected_sdks": []
    }

    subprocess.run(["apktool", "d", filepath, "-o", output_dir, "-f"],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
    if os.path.exists(manifest_path):
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            for perm in root.findall("uses-permission"):
                name = perm.attrib.get("{http://schemas.android.com/apk/res/android}name")
                if name:
                    result["permissions"].append(name)

            app_tag = root.find("application")
            if app_tag is not None:
                debuggable = app_tag.attrib.get("{http://schemas.android.com/apk/res/android}debuggable")
                if debuggable == "true":
                    result["debuggable"] = True

            for elem in root.iter():
                for attr in elem.attrib.values():
                    if isinstance(attr, str) and "http://" in attr:
                        result["uses_http"] = True
                        break
        except ET.ParseError:
            result["error"] = "Failed to parse AndroidManifest.xml"

    for root_dir, dirs, files in os.walk(output_dir):
        for file in files:
            if file.endswith(".smali"):
                path = os.path.join(root_dir, file)
                try:
                    with open(path, "r", errors="ignore") as f:
                        content = f.read()
                        secrets = re.findall(r'\\"?(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35}|[A-Za-z0-9]{32,})\\"?', content)
                        result["hardcoded_secrets"].extend(secrets)
                except Exception:
                    continue

    known_sdks = {
        "com.facebook": "Facebook SDK",
        "com.google.firebase": "Firebase SDK",
        "com.adjust": "Adjust SDK",
        "com.appsflyer": "AppsFlyer SDK",
        "com.onesignal": "OneSignal SDK",
        "com.ironsource": "IronSource SDK",
        "com.unity3d": "Unity Ads SDK",
        "com.chartboost": "Chartboost SDK",
        "com.vungle": "Vungle SDK"
    }

    for root_dir, dirs, _ in os.walk(output_dir):
        for dir_name in dirs:
            full_path = os.path.join(root_dir, dir_name)
            for sdk_prefix in known_sdks:
                if sdk_prefix.replace(".", "/") in full_path:
                    sdk_name = known_sdks[sdk_prefix]
                    if sdk_name not in result["detected_sdks"]:
                        result["detected_sdks"].append(sdk_name)

    result["insecure_webview_usage"] = []

    for root_dir, dirs, files in os.walk(output_dir):
        for file in files:
            if file.endswith(".smali"):
                path = os.path.join(root_dir, file)
                try:
                    with open(path, "r", errors="ignore") as f:
                        content = f.read()
                        if 'setJavaScriptEnabled' in content:
                            result["insecure_webview_usage"].append("setJavaScriptEnabled(true)")
                        if 'addJavascriptInterface' in content:
                            result["insecure_webview_usage"].append("addJavascriptInterface(...)")
                        if 'loadUrl("http://' in content or 'loadUrl("http' in content:
                            result["insecure_webview_usage"].append("loadUrl('http://...')")
                except Exception:
                    continue
        # Exported components
    result["exported_components"] = []

    component_tags = ["activity", "service", "receiver", "provider"]
    for tag in component_tags:
        for elem in root.findall(tag):
            exported = elem.attrib.get("{http://schemas.android.com/apk/res/android}exported")
            name = elem.attrib.get("{http://schemas.android.com/apk/res/android}name")
            if exported == "true":
                result["exported_components"].append(f"{tag}: {name}")

    return result

