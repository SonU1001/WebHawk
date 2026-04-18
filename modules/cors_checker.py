import requests

def check_cors(url):
    findings = []

    # 🔥 Malicious test origin
    test_origin = "http://evil.com"

    headers = {
        "Origin": test_origin
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)

        acao = response.headers.get("Access-Control-Allow-Origin")
        acac = response.headers.get("Access-Control-Allow-Credentials")

        # --- Case 1: Wildcard ---
        if acao == "*":
            findings.append({
                "type": "CORS Misconfiguration (Wildcard Origin)",
                "severity": "Medium",
                "details": "Server allows any origin (*)",
                "url": url
            })

        # --- Case 2: Reflected Origin ---
        elif acao == test_origin:
            findings.append({
                "type": "CORS Misconfiguration (Reflected Origin)",
                "severity": "High",
                "details": f"Server reflects arbitrary origin: {test_origin}",
                "url": url
            })

        # --- Case 3: Credentials + Reflection (VERY BAD) ---
        if acao == test_origin and acac == "true":
            findings.append({
                "type": "CORS Misconfiguration (Credentials + Origin Reflection)",
                "severity": "High",
                "details": "Server allows credentials with arbitrary origin",
                "url": url
            })

    except requests.exceptions.RequestException:
        pass

    return findings