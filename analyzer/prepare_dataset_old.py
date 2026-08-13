import pandas as pd
import os


OUTPUT = "datasets/enhanced_security_logs.csv"


# Security patterns used for initial labeling
PATTERNS = {
    "Brute Force Attack": [
        "failed password",
        "authentication failure",
        "invalid user",
        "possible break-in attempt",
        "failed login",
        "login failed",
        "multiple failed"
    ],

    "Privilege Escalation": [
        "sudo",
        "not in sudoers",
        "administrative privileges",
        "privilege escalation",
        "root access",
        "permission denied"
    ],

    "Malware Activity": [
        "malware",
        "virus",
        "trojan",
        "ransomware",
        "backdoor",
        "malicious file"
    ],

    "Suspicious Activity": [
        "suspicious",
        "unknown process",
        "unknown connection",
        "possible attack",
        "break-in"
    ]
}


def classify_log(text):
    text = str(text).lower()

    for label, patterns in PATTERNS.items():

        for pattern in patterns:

            if pattern in text:
                return label

    return "Normal Activity"


def load_log_file(path, source):

    rows = []

    if not os.path.exists(path):
        print(f"File not found: {path}")
        return rows

    with open(path, "r", errors="ignore") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            rows.append({
                "log": line,
                "source": source,
                "label": classify_log(line)
            })

    return rows


def main():

    all_rows = []

    datasets = [

        (
            "datasets/external/loghub/Linux/Linux_2k.log",
            "Linux"
        ),

        (
            "datasets/external/loghub/OpenSSH/OpenSSH_2k.log",
            "OpenSSH"
        ),

        (
            "datasets/external/loghub/Apache/Apache_2k.log",
            "Apache"
        ),

        (
            "datasets/external/loghub/Windows/Windows_2k.log",
            "Windows"
        )
    ]


    for path, source in datasets:

        print(f"Processing {source}...")

        rows = load_log_file(path, source)

        all_rows.extend(rows)


    # Add existing manually labeled dataset
    original = pd.read_csv("datasets/security_logs.csv")

    for _, row in original.iterrows():

        all_rows.append({
            "log": row["log"],
            "source": "Custom Dataset",
            "label": row["label"]
        })


    df = pd.DataFrame(all_rows)

    df = df.dropna(subset=["log", "label"])

    df = df.drop_duplicates(subset=["log"])

    df.to_csv(OUTPUT, index=False)

    print()
    print("Enhanced dataset created successfully!")
    print(f"Total samples: {len(df)}")
    print()
    print("Class distribution:")
    print(df["label"].value_counts())
    print()
    print("Source distribution:")
    print(df["source"].value_counts())


if __name__ == "__main__":
    main()
