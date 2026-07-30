import json

cves = [
    {
        "cve_id": "CVE-2021-23337",
        "package": "lodash",
        "version_affected": "<4.17.21",
        "cvss_score": 7.2,
        "epss_score": 0.42,
        "patch_status": "not_patched",
        "description": "Command injection via template function"
    },
    {
        "cve_id": "CVE-2022-24999",
        "package": "qs",
        "version_affected": "<6.7.3",
        "cvss_score": 9.8,
        "epss_score": 0.78,
        "patch_status": "not_patched",
        "description": "Prototype pollution leading to RCE"
    },
    {
        "cve_id": "CVE-2021-3918",
        "package": "json-schema",
        "version_affected": "<0.4.0",
        "cvss_score": 9.8,
        "epss_score": 0.65,
        "patch_status": "not_patched",
        "description": "Prototype pollution"
    },
]

with open("tests/fixtures/acmecorp_cves.json", "w") as f:
    json.dump(cves, f, indent=2)

print(f"{len(cves)} CVEs générées dans acmecorp_cves.json")