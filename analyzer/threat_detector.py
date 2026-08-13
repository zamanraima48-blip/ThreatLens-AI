from collections import Counter
import re


def detect_threats(log_text):

    threats = []
    lines = log_text.splitlines()

    failed_ips = []

    for line in lines:

        lower_line = line.lower()

        # ==========================================
        # Failed Login
        # ==========================================

        if re.search(
            r"failed password|authentication failure|invalid user|failed login",
            line,
            re.I
        ):
            threats.append({
                "type": "Failed Login",
                "severity": "Medium",
                "message": line
            })

            ip = re.search(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                line
            )

            if ip:
                failed_ips.append(ip.group())

        # ==========================================
        # Successful Login
        # ==========================================

        if re.search(
            r"accepted password|accepted publickey|login successful",
            line,
            re.I
        ):
            threats.append({
                "type": "Successful Login",
                "severity": "Low",
                "message": line
            })

        # ==========================================
        # SSH Attack
        # ==========================================

        if (
            "sshd" in lower_line
            and re.search(
                r"failed password|authentication failure|invalid user|failure",
                line,
                re.I
            )
        ):
            threats.append({
                "type": "SSH Attack",
                "severity": "High",
                "message": line
            })

        # ==========================================
        # Privilege Escalation
        # ==========================================

        if re.search(
            r"\bsudo\b.*(command|execut|failed|incorrect)",
            line,
            re.I
        ) or re.search(
            r"privilege escalation|root access|su:.*authentication failure",
            line,
            re.I
        ):
            threats.append({
                "type": "Privilege Escalation Attempt",
                "severity": "High",
                "message": line
            })

        # ==========================================
        # Suspicious Commands
        # ==========================================

        # Ignore systemd capability/build-feature lists such as:
        # "... +CURL +OPENSSL +BZIP2 ..."
        # These are not executed commands.

        is_systemd_feature_list = re.search(
            r"systemd.*(?:running in system mode|system mode).*"
            r"\+[A-Z0-9_]+",
            line,
            re.I
        )

        actual_suspicious_command = re.search(
            r"(?:COMMAND=|command=|cmd=|executed|exec|process).*?"
            r"\b(wget|curl|nc|netcat|chmod|bash\s+-i|python\s+-c)\b",
            line,
            re.I
        )

        if (
            not is_systemd_feature_list
            and actual_suspicious_command
        ):
            threats.append({
                "type": "Suspicious Command",
                "severity": "High",
                "message": line
            })

        # ==========================================
        # Unauthorized Access
        # ==========================================

        if re.search(
            r"unauthorized|permission denied|access denied|authentication failure",
            line,
            re.I
        ):
            threats.append({
                "type": "Unauthorized Access",
                "severity": "Medium",
                "message": line
            })

    # ==========================================
    # Malware Indicators + MITRE ATT&CK
    # ==========================================

    if re.search(
        r"\b(malware|virus|trojan|ransomware)\b",
        line,
        re.I
    ):
        threat = {
            "type": "Malware Indicator",
            "severity": "High",
            "message": line
        }

        # Ransomware behavior
        if re.search(
            r"ransomware|encrypt(ed|ion)?|encrypted files",
            line,
            re.I
        ):
            threat["mitre_technique"] = "T1486"
            threat["mitre_name"] = "Data Encrypted for Impact"

        # Malware execution
        elif re.search(
            r"execut(ed|ion)|started|launched|process",
            line,
            re.I
        ):
            threat["mitre_technique"] = "T1204"
            threat["mitre_name"] = "User Execution"

        threats.append(threat)

    # Suspicious executable indicators
    # Normal .exe/.dll filenames alone are NOT malware.
    if re.search(
        r"\b(suspicious|malicious|infected|unknown|payload|trojan|"
        r"virus|malware)\b.*\.(exe|dll)\b|"
        r"\.(exe|dll)\b.*\b(suspicious|malicious|infected|unknown|"
        r"payload|trojan|virus|malware)\b",
        line,
        re.I
    ):
        threats.append({
            "type": "Malware Indicator",
            "severity": "High",
            "message": line
        })

    # ==========================================
    # SQL Injection
    # ==========================================

    if re.search(
        r"union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|"
        r"'?\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1",
        line,
        re.I
    ):
        threats.append({
            "type": "SQL Injection Attempt",
            "severity": "High",
            "message": line
        })

    # ==========================================
    # Web Scanning
    # ==========================================

    if re.search(
        r"/admin\b|/phpmyadmin\b|/\.env\b|wp-login\.php|robots\.txt",
        line,
        re.I
    ):
        threats.append({
            "type": "Web Scanning Attempt",
            "severity": "Medium",
            "message": line
        })

    # ==========================================
    # XSS
    # ==========================================

    if re.search(
        r"<script|javascript:|alert\s*\(",
        line,
        re.I
    ):
        threats.append({
            "type": "XSS Attempt",
            "severity": "High",
            "message": line
        })

    # ==========================================
    # Brute Force Detection
    # ==========================================

    ip_counts = Counter(failed_ips)

    for ip, count in ip_counts.items():

        if count >= 5:

            threats.append({
                "type": "Brute Force Attack",
                "severity": "Critical",
                "source_ip": ip,
                "attempts": count,
                "message": (
                    f"{count} failed authentication attempts "
                    f"detected from {ip}"
    )
            })

    return threats
