import requests
import urllib.parse

def get_params(url):
    """
    Extract parameters from URL and return as dictionary
    Example: ?id=1&name=test → {'id': '1', 'name': 'test'}
    """
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.parse_qs(parsed.query)


def build_url(base_url, params):
    """
    Rebuild URL with modified parameters
    """
    parsed = urllib.parse.urlparse(base_url)
    query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=query))


def scan_xss(url):
    findings = []

    # 🔥 Multiple realistic payloads
    payloads = [
        "<script>alert(1)</script>",
        "\"'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    ]

    params = get_params(url)

    if not params:
        return findings

    for param in params:
        original_value = params[param][0]

        for payload in payloads:
            test_params = params.copy()
            test_params[param] = payload

            test_url = build_url(url, test_params)

            try:
                response = requests.get(test_url, timeout=5)

                # ✅ Reflection check
                if payload in response.text:

                    # ✅ Basic filtering check (reduce false positives)
                    if "<script>" in payload and "<script>" not in response.text:
                        continue

                    findings.append({
                        "type": "Reflected XSS",
                        "severity": "High",
                        "parameter": param,
                        "payload": payload,
                        "url": test_url
                    })

            except requests.exceptions.RequestException:
                continue

    return findings