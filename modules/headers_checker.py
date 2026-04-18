import requests

def check_headers(url):
    findings = []

    # 🔥 Important security headers with severity + explanation
    security_headers = {
        "Content-Security-Policy": {
            "severity": "High",
            "description": "Prevents XSS attacks by restricting content sources"
        },
        "X-Frame-Options": {
            "severity": "Medium",
            "description": "Prevents clickjacking attacks"
        },
        "Strict-Transport-Security": {
            "severity": "High",
            "description": "Forces HTTPS and prevents MITM attacks"
        },
        "X-Content-Type-Options": {
            "severity": "Low",
            "description": "Prevents MIME type sniffing"
        },
        "Referrer-Policy": {
            "severity": "Info",
            "description": "Controls how much referrer information is shared"
        }
    }

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        for header, info in security_headers.items():
            if header not in headers:
                findings.append({
                    "type": f"Missing Security Header: {header}",
                    "severity": info["severity"],
                    "description": info["description"],
                    "url": url
                })

    except requests.exceptions.RequestException:
        pass

    return findings