import pandas as pd
import os
import re

# ==========================================
# Paths
# ==========================================

BASE = "datasets/external/loghub"
OUTPUT = "datasets/sequence_security_logs.csv"

records = []


# ==========================================
# Helper: Extract IP addresses
# ==========================================

def extract_ip(text):

    match = re.search(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        str(text)
    )

    return match.group(0) if match else "unknown"


# ==========================================
# OpenSSH Sequence Analysis
# ==========================================

def process_openssh():

    path = os.path.join(
        BASE,
        "OpenSSH",
        "OpenSSH_2k.log_structured.csv"
    )

    df = pd.read_csv(path)

    print("Processing OpenSSH sequences...")

    for i, row in df.iterrows():

        content = str(row["Content"])

        # Look at a window of nearby events
        start = max(0, i - 5)
        end = min(len(df), i + 6)

        window = df.iloc[start:end]["Content"].astype(str)

        combined = " ".join(window)

        failed_password = len(
            re.findall(
                r"Failed password",
                combined,
                re.IGNORECASE
            )
        )

        auth_failure = len(
            re.findall(
                r"authentication failure",
                combined,
                re.IGNORECASE
            )
        )

        invalid_user = len(
            re.findall(
                r"Invalid user",
                combined,
                re.IGNORECASE
            )
        )

        break_in = bool(
            re.search(
                r"POSSIBLE BREAK-IN ATTEMPT",
                combined,
                re.IGNORECASE
            )
        )

        too_many = bool(
            re.search(
                r"Too many authentication failures",
                combined,
                re.IGNORECASE
            )
        )

        accepted = bool(
            re.search(
                r"Accepted password",
                content,
                re.IGNORECASE
            )
        )

        ip = extract_ip(content)

        # ======================================
        # Classification
        # ======================================

        if (
            failed_password >= 3
            or auth_failure >= 3
            or invalid_user >= 3
            or break_in
            or too_many
        ):

            label = "Brute Force Attack"

        elif accepted:

            label = "Normal Activity"

        elif (
            "Invalid user" in content
            or "authentication failure" in content.lower()
        ):

            label = "Suspicious Activity"

        else:

            label = "Normal Activity"

        records.append({

            "log": content,

            "label": label,

            "source": "OpenSSH",

            "failed_password_count": failed_password,

            "authentication_failure_count": auth_failure,

            "invalid_user_count": invalid_user,

            "break_in_attempt": int(break_in),

            "too_many_auth_failures": int(too_many),

            "accepted_password": int(accepted),

            "source_ip": ip

        })


# ==========================================
# Linux Sequence Analysis
# ==========================================

def process_linux():

    path = os.path.join(
        BASE,
        "Linux",
        "Linux_2k.log_structured.csv"
    )

    df = pd.read_csv(path)

    print("Processing Linux sequences...")

    for i, row in df.iterrows():

        content = str(row["Content"])

        start = max(0, i - 5)
        end = min(len(df), i + 6)

        window = df.iloc[start:end]["Content"].astype(str)

        combined = " ".join(window)

        auth_failure = len(
            re.findall(
                r"authentication failure",
                combined,
                re.IGNORECASE
            )
        )

        invalid_user = len(
            re.findall(
                r"check pass; user unknown|Invalid user",
                combined,
                re.IGNORECASE
            )
        )

        accepted = bool(
            re.search(
                r"Accepted password|session opened",
                content,
                re.IGNORECASE
            )
        )

        ip = extract_ip(content)

        if auth_failure >= 3 or invalid_user >= 3:

            label = "Brute Force Attack"

        elif accepted:

            label = "Normal Activity"

        elif auth_failure > 0 or invalid_user > 0:

            label = "Suspicious Activity"

        else:

            label = "Normal Activity"

        records.append({

            "log": content,

            "label": label,

            "source": "Linux",

            "failed_password_count": 0,

            "authentication_failure_count": auth_failure,

            "invalid_user_count": invalid_user,

            "break_in_attempt": 0,

            "too_many_auth_failures": 0,

            "accepted_password": int(accepted),

            "source_ip": ip

        })


# ==========================================
# Apache
# ==========================================

def process_apache():

    path = os.path.join(
        BASE,
        "Apache",
        "Apache_2k.log_structured.csv"
    )

    df = pd.read_csv(path)

    print("Processing Apache...")

    for _, row in df.iterrows():

        content = str(row["Content"])

        level = str(row.get("Level", ""))

        if level.lower() == "error":

            label = "Suspicious Activity"

        else:

            label = "Normal Activity"

        records.append({

            "log": content,

            "label": label,

            "source": "Apache",

            "failed_password_count": 0,

            "authentication_failure_count": 0,

            "invalid_user_count": 0,

            "break_in_attempt": 0,

            "too_many_auth_failures": 0,

            "accepted_password": 0,

            "source_ip": extract_ip(content)

        })


# ==========================================
# Windows
# ==========================================

def process_windows():

    path = os.path.join(
        BASE,
        "Windows",
        "Windows_2k.log_structured.csv"
    )

    df = pd.read_csv(path)

    print("Processing Windows...")

    for _, row in df.iterrows():

        content = str(row["Content"])

        level = str(row.get("Level", ""))

        if level.lower() in ["error", "warning"]:

            label = "Suspicious Activity"

        else:

            label = "Normal Activity"

        records.append({

            "log": content,

            "label": label,

            "source": "Windows",

            "failed_password_count": 0,

            "authentication_failure_count": 0,

            "invalid_user_count": 0,

            "break_in_attempt": 0,

            "too_many_auth_failures": 0,

            "accepted_password": 0,

            "source_ip": extract_ip(content)

        })


# ==========================================
# Run Processing
# ==========================================

process_linux()
process_openssh()
process_apache()
process_windows()


# ==========================================
# Save Dataset
# ==========================================

dataset = pd.DataFrame(records)

dataset.to_csv(
    OUTPUT,
    index=False
)

print()
print("==========================================")
print("Sequence-aware dataset created!")
print("==========================================")

print(f"Total samples: {len(dataset)}")

print()
print("Class distribution:")
print(
    dataset["label"]
    .value_counts()
    .to_string()
)

print()
print("Source distribution:")
print(
    dataset["source"]
    .value_counts()
    .to_string()
)

print()
print(f"Saved to: {OUTPUT}")
