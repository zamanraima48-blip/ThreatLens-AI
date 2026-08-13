import json


def map_attack(threat_text):

    with open("mitre/attack_data.json", "r") as f:
        techniques = json.load(f)

    matches = []

    threat_text = threat_text.lower()

    for technique in techniques:
        for keyword in technique["keywords"]:
            if keyword in threat_text:
                matches.append({
                    "Technique ID": technique["technique_id"],
                    "Technique": technique["technique"],
                    "Tactic": technique["tactic"]
                })
                break

    return matches
