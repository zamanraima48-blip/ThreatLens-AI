import re


def extract_ips(text):
    pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return list(set(re.findall(pattern, text)))


def extract_domains(text):
    pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    domains = re.findall(pattern, text)

    filtered_domains = []

    for domain in domains:
        # Ignore file extensions
        if not re.search(
            r'\.(exe|dll|sh|bin|py|bat|ps1|vbs|elf)$',
            domain,
            re.IGNORECASE
        ):
            filtered_domains.append(domain)

    return list(set(filtered_domains))


def extract_urls(text):
    pattern = r'https?://[^\s]+'
    return list(set(re.findall(pattern, text)))


def extract_emails(text):
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(pattern, text)))


def extract_md5(text):
    pattern = r'\b[a-fA-F0-9]{32}\b'
    return list(set(re.findall(pattern, text)))


def extract_sha1(text):
    pattern = r'\b[a-fA-F0-9]{40}\b'
    return list(set(re.findall(pattern, text)))


def extract_sha256(text):
    pattern = r'\b[a-fA-F0-9]{64}\b'
    return list(set(re.findall(pattern, text)))


def extract_filenames(text):
    pattern = r'\b[A-Za-z0-9._-]+\.(exe|dll|elf|sh|bin|py|bat|ps1|vbs)\b'

    return list(set(
        re.findall(
            r'\b[A-Za-z0-9._-]+\.(?:exe|dll|elf|sh|bin|py|bat|ps1|vbs)\b',
            text,
            re.IGNORECASE
        )
    ))


def extract_iocs(text):

    return {
        "ip_addresses": extract_ips(text),
        "domains": extract_domains(text),
        "urls": extract_urls(text),
        "emails": extract_emails(text),
        "md5": extract_md5(text),
        "sha1": extract_sha1(text),
        "sha256": extract_sha256(text),
        "suspicious_files": extract_filenames(text)
    }
