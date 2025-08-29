import pandas as pd 
import json as js

THREAT_KEYWORDS = {
    "Remote Code Execution": ["remote code execution", "rce"],
    "Privilege Escalation": ["privilege escalation", "elevation of privilege"],
    "Denial of Service": ["denial of service", "dos attack"],
    "Information Disclosure": ["information disclosure", "data leak"],
    "Buffer Overflow": ["buffer overflow"],
    "SQL Injection": ["sql injection"],
    "Cross-Site Scripting": ["xss", "cross-site scripting"],
    "Authentication Bypass": ["authentication bypass"],
    "Insecure Defaults": ["default password", "insecure default"],
    "Command Injection": ["command injection"]
}


def label_threat(description):
    description = str(description).lower()
    for threat, keywords in THREAT_KEYWORDS.items():
        for keyword in keywords:
            if keyword in description:
                return threat
    return "Other"


csv_df = pd.read_csv("ctad_data/allitems.csv", encoding='latin1', low_memory=False)
csv_df = csv_df.dropna(subset=["Name", "Description"])
csv_df["Threat_Type"] = csv_df["Description"].apply(label_threat)

# Load JSON
with open("ctad_data/nvdcve-2.0-modified.json", "r", encoding="utf-8") as f:
    json_data = js.load(f)

json_records = []
for item in json_data.get("vulnerabilities", []):
    cve_id = item.get("cve", {}).get("id", "Unknown")
    descs = item.get("cve", {}).get("descriptions", [])
    if descs:
        description = descs[0].get("value", "")
        if description:
            threat = label_threat(description)
            json_records.append({"Name": cve_id, "Description": description, "Threat_Type": threat})

# Combine both
json_df = pd.DataFrame(json_records)
combined_df = pd.concat([csv_df[["Name", "Description", "Threat_Type"]], json_df], ignore_index=True)
combined_df = combined_df.drop_duplicates()
combined_df.to_csv("labeled_cves.csv", index=False)

print("labeled_cves.csv")



