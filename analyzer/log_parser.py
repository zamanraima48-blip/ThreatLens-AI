import re


def parse_log(file_path):
    """
    Read log file line by line.
    Extract timestamp, hostname, process and message.
    Returns structured log entries.
    """

    parsed_logs = []

    with open(file_path, "r", errors="ignore") as file:

        for line in file:
            line = line.strip()

            if not line:
                continue

            # Detect timestamp (Linux syslog format)
            timestamp_match = re.match(
                r"([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)",
                line
            )

            timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"


            # Detect hostname
            hostname_match = re.search(
                r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d+:\d+:\d+\s+(\S+)",
                line
            )

            hostname = hostname_match.group(1) if hostname_match else "Unknown"


            # Detect process name
            process_match = re.search(
               r"\s([a-zA-Z0-9_-]+)\[\d+\]:",
               line
             )
            process = process_match.group(1) if process_match else "Unknown"

            # Detect username
            username_match = re.search(
                r"for (\w+)",
                line
            )

            username = username_match.group(1) if username_match else "Unknown"
            # Remove first parts and keep message
            message = line

            log_entry = {
                "timestamp": timestamp,
                "hostname": hostname,
                "process": process,
                "username": username,
                "message": message
            }
            parsed_logs.append(log_entry)

    return parsed_logs
