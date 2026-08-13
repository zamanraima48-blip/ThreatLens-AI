import pickle
from analyzer.threat_detector import detect_threats
from collections import Counter
import re

MODEL_PATH = "ai/multiclass_threat_model.pkl"

# ==========================================
# Load 5-Class AI Model
# ==========================================

with open(MODEL_PATH, "rb") as file:
    model = pickle.load(file)


# ==========================================
# Extract Security Evidence
# ==========================================

def extract_evidence(log_text):

    text = str(log_text)
    evidence = []

    patterns = [
        (
            r"Failed password",
            "Failed password authentication attempt detected"
        ),
        (
            r"authentication failure",
            "Authentication failure detected"
        ),
        (
            r"Invalid user",
            "Invalid user attempt detected"
        ),
        (
            r"POSSIBLE BREAK-IN ATTEMPT",
            "Possible break-in attempt detected"
        ),
        (
            r"Too many authentication failures",
            "Too many authentication failures detected"
        ),
        (
            r"\bsudo\b|privilege escalation|administrative privileges",
            "Privileged access activity detected"
        ),
        (
            r"\bmalware\b|\bvirus\b|\btrojan\b|malicious file|malicious software",
            "Malware-related indicator detected"
        ),
        (
            r"\.exe\b|\.(dll)\b",
            "Suspicious executable file indicator detected"
        ),
        (
            r"<script>|</script>|javascript:|alert\s*\(",
            "Possible XSS pattern detected"
        ),
        (
            r"union\s+select|select.*from|insert\s+into|drop\s+table",
            "Possible SQL injection pattern detected"
        ),
        (
            r"/admin|/phpmyadmin|/\.env|wp-login|robots\.txt",
            "Possible web reconnaissance activity detected"
        ),
        (
            r"\bwget\b|\bcurl\b|\bnc\b|\bnetcat\b|chmod|bash\s+-i|python\s+-c",
            "Suspicious command-line activity detected"
        )
    ]

    for pattern, description in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            evidence.append(description)

    if not evidence:
        evidence.append("No strong security indicators detected")

    return evidence


# ==========================================
# Extract Suspicious IP Addresses
# ==========================================

def extract_suspicious_ips(log_text):

    text = str(log_text)

    security_lines = re.findall(
        r".*(?:Failed password|authentication failure|Invalid user|"
        r"POSSIBLE BREAK-IN ATTEMPT|Too many authentication failures).*",
        text,
        re.IGNORECASE
    )

    ip_counts = {}

    for line in security_lines:

        ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            line
        )

        for ip in ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    sorted_ips = sorted(
        ip_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return [
        {
            "ip": ip,
            "events": count
        }
        for ip, count in sorted_ips
        if count >= 3
    ]


# ==========================================
# AI Threat Classification
# ==========================================

def classify_threat(log_text):

    text = str(log_text)

    # AI is now the PRIMARY classifier.
    prediction = model.predict([text])[0]

    return prediction


# ==========================================
# AI Confidence
# ==========================================

def get_confidence(log_text):

    try:

        probabilities = model.predict_proba([str(log_text)])[0]

        confidence = max(probabilities) * 100

        return round(float(confidence), 2)

    except Exception:

        return 0.0


# ==========================================
# Threat Explanation
# ==========================================

def explain_threat(threat, evidence):

    explanations = {

        "Brute Force Attack":
            "The AI model identified authentication patterns "
            "consistent with password guessing or repeated "
            "login attempts.",

        "Malware Activity":
            "The AI model identified activity associated with "
            "malware, malicious files, or malicious software.",

        "Privilege Escalation":
            "The AI model identified activity associated with "
            "unauthorized or elevated privileges.",

        "Suspicious Activity":
            "The AI model identified activity that deviates "
            "from normal system behavior and requires investigation.",

        "Normal Activity":
            "The AI model identified the activity as consistent "
            "with normal system behavior."
    }

    return explanations.get(
        threat,
        "The AI model identified potentially suspicious activity "
        "requiring further investigation."
    )


# ==========================================
# Security Recommendations
# ==========================================

def get_recommendations(threat):

    recommendations = {

        "Brute Force Attack": [
            "Investigate the source IP addresses",
            "Enable multi-factor authentication",
            "Monitor authentication logs",
            "Consider SSH rate limiting or fail2ban"
        ],

        "Malware Activity": [
            "Investigate the affected host",
            "Run an endpoint malware scan",
            "Isolate the affected system if necessary",
            "Investigate suspicious files and processes"
        ],

        "Privilege Escalation": [
            "Review user permissions",
            "Audit privileged accounts",
            "Investigate recent privilege changes",
            "Apply the principle of least privilege"
        ],

        "Suspicious Activity": [
            "Investigate the associated log activity",
            "Review source and destination information",
            "Correlate with other security events",
            "Continue monitoring the affected system"
        ],

        "Normal Activity": [
            "Continue normal security monitoring"
        ]
    }

    return recommendations.get(
        threat,
        ["Manual investigation required"]
    )


# ==========================================
# Complete AI Incident Analysis
# ==========================================

def analyze_incident(log_text):
    """
    Evidence-aware incident analysis.

    The ML model provides the baseline prediction, while the
    deterministic threat detector provides security evidence.
    Strong detected threats take precedence over a generic
    'Normal Activity' ML prediction.
    """

    text = str(log_text)

    # ======================================
    # ML BASELINE
    # ======================================

    try:
        ml_threat = classify_threat(text)
        ml_confidence = get_confidence(text)
    except Exception:
        ml_threat = "Normal Activity"
        ml_confidence = 0.0

    # ======================================
    # SECURITY EVIDENCE
    # ======================================

    try:
        detected_threats = detect_threats(text)
    except Exception:
        detected_threats = []

    threat_counts = Counter(
        threat.get("type", "Unknown")
        for threat in detected_threats
        if isinstance(threat, dict)
    )

    # ======================================
    # EVIDENCE-BASED CLASSIFICATION
    # ======================================

    brute_force_count = threat_counts.get(
        "Brute Force Attack",
        0
    )

    malware_count = threat_counts.get(
        "Malware Indicator",
        0
    )

    privilege_count = threat_counts.get(
        "Privilege Escalation Attempt",
        0
    )

    suspicious_command_count = threat_counts.get(
        "Suspicious Command",
        0
    )

    sql_count = threat_counts.get(
        "SQL Injection Attempt",
        0
    )

    xss_count = threat_counts.get(
        "XSS Attempt",
        0
    )

    web_scan_count = threat_counts.get(
        "Web Scanning Attempt",
        0
    )

    failed_login_count = threat_counts.get(
        "Failed Login",
        0
    )

    ssh_attack_count = threat_counts.get(
        "SSH Attack",
        0
    )

    unauthorized_count = threat_counts.get(
        "Unauthorized Access",
        0
    )

    # ======================================
    # Strong evidence has priority over
    # generic ML "Normal Activity"
    # ======================================

    if brute_force_count > 0:
        threat = "Brute Force Attack"

    elif malware_count > 0:
        threat = "Malware Activity"

    elif privilege_count > 0:
        threat = "Privilege Escalation"

    elif sql_count > 0 or xss_count > 0 or web_scan_count > 0:
        threat = "Suspicious Activity"

    elif (
        suspicious_command_count > 0
        or ssh_attack_count > 0
        or unauthorized_count > 0
        or failed_login_count > 0
    ):
        threat = "Suspicious Activity"

    else:
        threat = ml_threat

    # ======================================
    # Confidence
    # ======================================

    if threat != ml_threat:
        confidence = max(
            float(ml_confidence),
            95.0 if brute_force_count > 0 else 85.0
        )
    else:
        confidence = float(ml_confidence)

    confidence = round(
        min(confidence, 99.99),
        2
    )

    # ======================================
    # Severity
    # ======================================

    if brute_force_count > 0:
        severity = "Critical"

    elif malware_count > 0:
        severity = "Critical"

    elif privilege_count > 0:
        severity = "Critical"

    elif sql_count > 0 or xss_count > 0:
        severity = "High"

    elif (
        suspicious_command_count > 0
        or ssh_attack_count > 0
        or unauthorized_count > 0
        or failed_login_count > 0
        or web_scan_count > 0
    ):
        severity = "High"

    elif threat == "Suspicious Activity":
        severity = "Medium"

    else:
        severity = "Low"

    # ======================================
    # Evidence
    # ======================================

    evidence = extract_evidence(text)

    if not evidence:
        evidence = []

    if brute_force_count > 0:
        evidence.insert(
            0,
            f"{brute_force_count} brute-force incident(s) detected"
        )

    if failed_login_count > 0:
        evidence.append(
            f"{failed_login_count} failed login event(s) detected"
        )

    if ssh_attack_count > 0:
        evidence.append(
            f"{ssh_attack_count} SSH attack event(s) detected"
        )

    if malware_count > 0:
        evidence.append(
            f"{malware_count} malware indicator(s) detected"
        )

    if privilege_count > 0:
        evidence.append(
            f"{privilege_count} privilege escalation attempt(s) detected"
        )

    # Remove duplicate evidence while preserving order
    evidence = list(dict.fromkeys(evidence))

    if not evidence:
        evidence = [
            "No strong security indicators detected"
        ]

    # ======================================
    # Suspicious IPs
    # ======================================

    suspicious_ips = extract_suspicious_ips(text)

    # ======================================
    # Explanation
    # ======================================

    if brute_force_count > 0:
        explanation = (
            f"The security analysis detected "
            f"{brute_force_count} brute-force incident(s) "
            f"based on repeated failed authentication activity. "
            f"The evidence-based classification takes precedence "
            f"over the generic ML prediction."
        )

    elif malware_count > 0:
        explanation = (
            "The security analysis identified malware-related "
            "indicators in the supplied log."
        )

    elif privilege_count > 0:
        explanation = (
            "The security analysis identified activity associated "
            "with privilege escalation."
        )

    elif sql_count > 0:
        explanation = (
            "The security analysis identified possible SQL injection "
            "activity."
        )

    elif xss_count > 0:
        explanation = (
            "The security analysis identified possible XSS activity."
        )

    elif threat == "Suspicious Activity":
        explanation = (
            "The security analysis identified suspicious activity "
            "requiring further investigation."
        )

    else:
        explanation = explain_threat(
            threat,
            evidence
        )

    # ======================================
    # Final Analysis
    # ======================================

    analysis = {

        "Incident Summary":
            f"{threat} detected with "
            f"{confidence}% AI confidence.",

        "Threat Classification":
            threat,

        "Confidence":
            f"{confidence}%",

        "Severity":
            severity,

        "Evidence":
            evidence,

        "Suspicious IPs":
            suspicious_ips,

        "Threat Explanation":
            explanation,

        "Security Recommendations":
            get_recommendations(threat),

        "Executive Summary":
            (
                f"The AI security analyzer classified the "
                f"activity as {threat} with {confidence}% "
                f"confidence and {severity} severity."
            ),

        "ML Baseline Classification":
            ml_threat,

        "ML Baseline Confidence":
            f"{round(float(ml_confidence), 2)}%",

        "Detected Threat Counts":
            dict(threat_counts)
    }

    return analysis

