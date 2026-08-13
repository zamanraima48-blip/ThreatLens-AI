from flask import Flask, request, render_template, redirect, url_for, session, send_file
from analyzer.log_parser import parse_log
from analyzer.ioc_extractor import extract_iocs
from analyzer.threat_detector import detect_threats
from ai.ai_analyzer import analyze_incident
from mitre.mitre_mapper import map_attack
import os
from pathlib import Path
import subprocess
from collections import Counter
from werkzeug.utils import secure_filename
from report_generator import generate_report

import re
import json

app = Flask(__name__)

app.secret_key = "threatlens-secret-key"

# ==========================================
# File Upload Configuration
# ==========================================

UPLOAD_FOLDER = "uploads"

ALLOWED_EXTENSIONS = {
    "log",
    "txt",
    "json",
    "csv",
    "xml",
    "evtx"
}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ==========================================
# Risk Assessment
# ==========================================

def calculate_risk(severity):

    risk_scores = {
        "Low": 25,
        "Medium": 50,
        "High": 75,
        "Critical": 95
    }

    score = risk_scores.get(severity, 0)

    explanations = {
        "Low": "Low risk activity detected. Continue monitoring.",
        "Medium": "Moderate risk activity detected. Further investigation is recommended.",
        "High": "High risk activity detected. Immediate investigation and security controls are recommended.",
        "Critical": "Critical security activity detected. Immediate response and containment are recommended."
    }

    return {
        "score": score,
        "explanation": explanations.get(
            severity,
            "Risk level could not be determined."
        )
    }


# ==========================================
# Live Journal Log Scanner
# ==========================================

# ==========================================
# Check File Extension
# ==========================================

def allowed_file(filename):

    return (
        "." in filename
        and
        filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# ==========================================
# Upload Logs Route
# ==========================================

@app.route("/upload", methods=["POST"])
def upload_file():

    if "logfile" not in request.files:

        return {
            "status": "error",
            "message": "No file selected"
        }, 400

    file = request.files["logfile"]

    log_type = request.form.get("log_type")

    if file.filename == "":

        return {
            "status": "error",
            "message": "No file selected"
        }, 400

    if not allowed_file(file.filename):

        return {
            "status": "error",
            "message": "Unsupported File Type"
        }, 400

    filename = secure_filename(file.filename)

    save_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(save_path)

    # ==========================================
    # Log Parsing
    # ==========================================

    parsed_logs = parse_log(save_path)

    with open(save_path, "r", errors="ignore") as f:
        log_text = f.read()

    # ==========================================
    # IOC Extraction
    # ==========================================

    iocs = extract_iocs(log_text)

    # ==========================================
    # Threat Detection
    # ==========================================

    threats = detect_threats(log_text)

    # ==========================================
    # MITRE ATT&CK Mapping
    # ==========================================

    mitre_mapping = []

    for threat in threats:
        attack_type = threat.get(
            "type",
            ""
        )

        mapping = map_attack(
            attack_type
        )

        if mapping:
            mitre_mapping.extend(mapping)


    # ==========================================
    # Remove Duplicate MITRE Techniques
    # ==========================================

    unique_mitre = {}

    for item in mitre_mapping:
        technique_id = item.get(
            "Technique ID",
            ""
        )

        if technique_id:
            unique_mitre[technique_id] = item

    mitre_mapping = list(
        unique_mitre.values()
    )


    # ==========================================
    # AI Security Analysis
    # ==========================================

    try:

        # Run the ML analyzer ONCE for the complete uploaded log.
        # Do not classify every security-relevant line separately.
        ai_analysis = analyze_incident(log_text)

        # Rule-based threat detection is authoritative when
        # strong security evidence has already been detected.
        if threats:

            threat_counts = Counter(
                t.get("type", "Unknown")
                for t in threats
            )

            if threat_counts.get("Brute Force Attack", 0) > 0:

                brute_force_count = threat_counts[
                    "Brute Force Attack"
                ]

                ai_analysis["Threat Classification"] = (
                    "Brute Force Attack"
                )

                ai_analysis["Severity"] = "Critical"

                ai_analysis["Incident Summary"] = (
                    "Brute Force Attack detected "
                    "in uploaded security logs."
                )

                ai_analysis["Executive Summary"] = (
                    f"The security analyzer detected "
                    f"{brute_force_count} brute-force incident(s) "
                    "in the uploaded log."
                )

                ai_analysis["Threat Explanation"] = (
                    f"ThreatLens AI identified {brute_force_count} "
                    "brute-force incident(s) based on repeated failed "
                    "authentication activity in the uploaded security logs. "
                    "The activity indicates possible credential-guessing or "
                    "unauthorized access attempts and should be investigated."
                )

    except Exception as e:

        ai_analysis = {
            "error": str(e)
        }

    # ==========================================
    # Risk Assessment
    # ==========================================

    if "error" not in ai_analysis:
        severity = ai_analysis.get(
            "Severity",
            "Low"
        )

        risk = calculate_risk(severity)

        ai_analysis["Risk Score"] = risk["score"]

        ai_analysis["Risk Explanation"] = risk["explanation"]


# ==========================================
# Final Response
# ==========================================

    uploaded_result = {
        "status": "success",
        "mode": "Uploaded Log Analysis",
        "filename": filename,
        "total_logs": len(parsed_logs),
        "total_iocs": len(iocs.get("ip_addresses", []))
            + len(iocs.get("domains", []))
            + len(iocs.get("urls", []))
            + len(iocs.get("emails", []))
            + len(iocs.get("md5", []))
            + len(iocs.get("sha1", []))
            + len(iocs.get("sha256", []))
            + len(iocs.get("suspicious_files", [])),
        "total_threats_detected": len(threats),
        "risk_score": ai_analysis.get("Risk Score", 0),
        "severity": ai_analysis.get("Severity", "Low"),
        "risk_explanation": ai_analysis.get(
            "Risk Explanation",
            "No risk assessment available."
        ),
        "iocs": iocs,
        "threats": threats,
        "mitre_mapping": mitre_mapping,
        "ai_analysis": ai_analysis
    }

    import json

    with open("runtime_results/uploaded_result.json", "w") as result_file:
        json.dump(uploaded_result, result_file)

    session["active_scan"] = "uploaded"
    session["uploaded_result_file"] = "runtime_results/uploaded_result.json"

    if request.form.get("redirect_to_dashboard") == "1":
        return redirect(url_for("dashboard"))

    return {

       "status": "success",

       "message": "File Uploaded Successfully",

       "log_type": log_type,

       "filename": filename,

       "saved_to": save_path,

       "total_lines": len(parsed_logs),

       "sample_logs": parsed_logs[:5],

       "iocs": iocs,

       "threats": threats,

       "mitre_mapping": mitre_mapping,

       "ai_analysis": ai_analysis

   }

# ==========================================
# Live System Journal Scan Route
# ==========================================

# ==========================================
# Home Page
# ==========================================

@app.route("/")
def home():

    return render_template("index.html")

@app.route("/dashboard")
def dashboard():

    try:

        active_scan = session.get("active_scan")

        # ==========================================
        # Select ONLY the currently active scan
        # ==========================================

        if active_scan == "uploaded":

            result_file = session.get(
                "uploaded_result_file"
            )

            if (
                not result_file
                or not Path(result_file).exists()
            ):
                live_scan = None
            else:
                with open(result_file, "r") as f:
                    live_scan = json.load(f)

        elif active_scan == "live":

            live_scan = session.get(
                "live_scan"
            )

        else:

            live_scan = None

        # ==========================================
        # Build Dashboard Data
        # ==========================================

        if live_scan and live_scan.get("status") == "success":

            live_threats = live_scan.get(
                "threats",
                []
            )

            live_iocs = live_scan.get(
                "iocs",
                {}
            )

            live_mitre = live_scan.get(
                "mitre_mapping",
                []
            )

            live_ai = live_scan.get(
                "ai_analysis",
                {}
            )

            if active_scan == "uploaded":

                analysis_mode = "Uploaded Log Analysis"
                default_filename = "Uploaded Log"

            else:

                analysis_mode = "Live System Scan"
                default_filename = "Live System Journal"

            data = {

                "analysis_mode":
                    analysis_mode,

                "filename":
                    live_scan.get(
                        "filename",
                        default_filename
                    ),

                "total_lines":
                    live_scan.get(
                        "total_logs",
                        0
                    ),

                "total_iocs":
                    live_scan.get(
                        "total_iocs",
                        len(live_iocs)
                        if isinstance(live_iocs, list)
                        else sum(
                            len(v)
                            for v in live_iocs.values()
                            if isinstance(v, list)
                        )
                    ),

                "total_threats":
                    live_scan.get(
                        "total_threats_detected",
                        len(live_threats)
                    ),

                "risk_score":
                    live_scan.get(
                        "risk_score",
                        0
                    ),

                "severity":
                    live_scan.get(
                        "severity",
                        "Low"
                    ),

                "risk_explanation":
                    live_scan.get(
                        "risk_explanation",
                        "No risk assessment available."
                    ),

                "threat_classification":
                    live_ai.get(
                        "Threat Classification",
                        "Security Log Analysis"
                    ) if isinstance(live_ai, dict)
                    else "Security Log Analysis",

                "executive_summary":
                    live_ai.get(
                        "Executive Summary",
                        "Security analysis completed successfully."
                    ) if isinstance(live_ai, dict)
                    else "Security analysis completed successfully.",

                "threat_explanation":
                    live_ai.get(
                        "Threat Explanation",
                        live_ai.get(
                            "Incident Summary",
                            f"{len(live_threats)} threats detected."
                        )
                    ) if isinstance(live_ai, dict)
                    else f"{len(live_threats)} threats detected.",

                "mitre_count":
                    len(live_mitre),

                "mitre_mapping":
                    live_mitre,

                "threats":
                    live_threats,

                "iocs":
                    live_iocs,

                "attack_labels":
                    live_scan.get(
                        "attack_labels",
                        []
                    ),

                "attack_values":
                    live_scan.get(
                        "attack_values",
                        []
                    )
            }

        else:

            data = {

                "analysis_mode":
                    "Security Log Analysis",

                "filename":
                    "No active scan",

                "total_lines": 0,

                "total_iocs": 0,

                "total_threats": 0,

                "risk_score": 0,

                "severity": "Low",

                "risk_explanation":
                    "No scan result available.",

                "threat_classification":
                    "No Analysis",

                "executive_summary":
                    "Please upload a security log or start a live scan.",

                "threat_explanation":
                    "No threat analysis available.",

                "mitre_count": 0,

                "mitre_mapping": [],

                "threats": [],

                "iocs": {},

                "attack_labels": [],

                "attack_values": []
            }

        return render_template(
            "dashboard.html",
            data=data
        )

    except Exception as e:

        return render_template(
            "dashboard.html",
            data={
                "analysis_mode": "Error",
                "filename": "Dashboard Error",
                "total_lines": 0,
                "total_iocs": 0,
                "total_threats": 0,
                "risk_score": 0,
                "severity": "Low",
                "risk_explanation":
                    "Dashboard error: " + str(e),
                "threat_classification": "Error",
                "executive_summary":
                    "Dashboard could not load.",
                "threat_explanation": str(e),
                "mitre_count": 0,
                "mitre_mapping": [],
                "threats": [],
                "iocs": {},
                "attack_labels": [],
                "attack_values": []
            }
        )


# ==========================================
# PDF Security Report
# ==========================================

@app.route("/generate_report")
def generate_pdf_report():

    try:

        # ==========================================
        # Select current scan result
        # ==========================================

        live_scan = session.get("live_scan")

        uploaded_result = None
        uploaded_result_path = session.get(
            "uploaded_result_file"
        )

        if uploaded_result_path:
            try:
                with open(
                    uploaded_result_path,
                    "r"
                ) as result_file:
                    uploaded_result = json.load(
                        result_file
                    )
            except Exception:
                uploaded_result = None

        # ==========================================
        # Prefer uploaded result when active
        # ==========================================

        if (
            session.get("active_scan") == "uploaded"
            and uploaded_result
            and uploaded_result.get("status") == "success"
        ):

            data = {
                "analysis_mode": "Uploaded Log Analysis",
                "filename": uploaded_result.get(
                    "filename",
                    "Uploaded Log"
                ),
                "total_lines": uploaded_result.get(
                    "total_logs",
                    0
                ),
                "total_iocs": uploaded_result.get(
                    "total_iocs",
                    0
                ),
                "total_threats": uploaded_result.get(
                    "total_threats_detected",
                    0
                ),
                "risk_score": uploaded_result.get(
                    "risk_score",
                    0
                ),
                "severity": uploaded_result.get(
                    "severity",
                    "Low"
                ),
                "risk_explanation": uploaded_result.get(
                    "risk_explanation",
                    "Risk assessment unavailable."
                ),
                "threat_classification": uploaded_result.get(
                    "ai_analysis",
                    {}
                ).get(
                    "Threat Classification",
                    "Security Log Analysis"
                ),
                "executive_summary": uploaded_result.get(
                    "ai_analysis",
                    {}
                ).get(
                    "Executive Summary",
                    "Uploaded security log analysis completed."
                ),
                "threat_explanation": uploaded_result.get(
                    "ai_analysis",
                    {}
                ).get(
                    "Incident Summary",
                    "No threat explanation available."
                ),
                "mitre_count": len(
                    uploaded_result.get(
                        "mitre_mapping",
                        []
                    )
                ),
                "mitre_mapping": uploaded_result.get(
                    "mitre_mapping",
                    []
                ),
                "threats": uploaded_result.get(
                    "threats",
                    []
                ),
                "iocs": uploaded_result.get(
                    "iocs",
                    {}
                ),
                "attack_labels": uploaded_result.get(
                    "attack_labels",
                    []
                ),
                "attack_values": uploaded_result.get(
                    "attack_values",
                    []
                )
            }

        elif (
            live_scan
            and live_scan.get("status") == "success"
        ):

            data = {
                "analysis_mode": "Live System Scan",
                "total_lines": live_scan.get(
                    "total_logs",
                    0
                ),
                "total_iocs": len(
                    live_scan.get("iocs", [])
                ),
                "total_threats": len(
                    live_scan.get("threats", [])
                ),
                "risk_score": live_scan.get(
                    "risk_score",
                    0
                ),
                "severity": live_scan.get(
                    "severity",
                    "Low"
                ),
                "risk_explanation": live_scan.get(
                    "risk_explanation",
                    "Risk assessment unavailable."
                ),
                "threat_classification": live_scan.get(
                    "threat_classification",
                    "Security Log Analysis"
                ),
                "executive_summary": live_scan.get(
                    "executive_summary",
                    "Live system security analysis completed."
                ),
                "threat_explanation": live_scan.get(
                    "threat_explanation",
                    "No threat explanation available."
                ),
                "mitre_count": len(
                    live_scan.get(
                        "mitre_mapping",
                        []
                    )
                ),
                "mitre_mapping": live_scan.get(
                    "mitre_mapping",
                    []
                ),
                "threats": live_scan.get(
                    "threats",
                    []
                ),
                "iocs": live_scan.get(
                    "iocs",
                    {}
                ),
                "attack_labels": live_scan.get(
                    "attack_labels",
                    []
                ),
                "attack_values": live_scan.get(
                    "attack_values",
                    []
                )
            }

        else:

            data = {
                "analysis_mode": "Security Log Analysis",
                "total_lines": 0,
                "total_iocs": 0,
                "total_threats": 0,
                "risk_score": 0,
                "severity": "Low",
                "risk_explanation": "No scan data available.",
                "threat_classification": "Security Log Analysis",
                "executive_summary": "No security analysis is currently available.",
                "threat_explanation": "Run an upload scan or live scan before generating the report.",
                "mitre_count": 0,
                "mitre_mapping": [],
                "threats": [],
                "iocs": {},
                "attack_labels": [],
                "attack_values": []
            }

        # ==========================================
        # Generate PDF
        # ==========================================

        output_path = (
            "reports/ThreatLens_AI_Report.pdf"
        )

        os.makedirs(
            "reports",
            exist_ok=True
        )

        generate_report(
            data,
            output_path
        )

        return send_file(
            output_path,
            as_attachment=False,
            download_name="ThreatLens_AI_Report.pdf",
            mimetype="application/pdf"
        )

    except Exception as e:

        return {
            "error": "Report generation failed",
            "details": str(e)
        }, 500

# ==========================================
# Run Flask
# ==========================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
