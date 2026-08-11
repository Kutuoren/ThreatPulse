import urllib.request
import json

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def handler(request):
    try:
        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={"User-Agent": "ThreatPulse/2.0 (security research)"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read(10 * 1024 * 1024)  # 10 MB cap

        data  = json.loads(raw.decode())
        vulns = data.get("vulnerabilities", [])

        # Return only the fields the frontend needs
        result = [
            {
                "cveID":             v.get("cveID", ""),
                "vendorProject":     v.get("vendorProject", ""),
                "product":           v.get("product", ""),
                "vulnerabilityName": v.get("vulnerabilityName", ""),
                "dateAdded":         v.get("dateAdded", ""),
                "shortDescription":  v.get("shortDescription", ""),
            }
            for v in vulns
        ]

        # Sort newest first
        result.sort(key=lambda x: x["dateAdded"], reverse=True)

        body    = json.dumps(result, ensure_ascii=False)
        headers = {
            "Content-Type":              "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control":             "s-maxage=3600, stale-while-revalidate",
            "X-Content-Type-Options":    "nosniff",
            "X-Frame-Options":           "DENY",
        }
        return {"statusCode": 200, "headers": headers, "body": body}

    except Exception as e:
        error = json.dumps({"error": str(e)})
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": error,
        }
