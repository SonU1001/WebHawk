import requests
import urllib.parse

def get_params(url):
    """
    Extract query parameters from URL
    """
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.parse_qs(parsed.query)


def build_url(base_url, params):
    """
    Rebuild URL with updated parameters
    """
    parsed = urllib.parse.urlparse(base_url)
    query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=query))


def check_redirect(url):
    findings = []

    # 🔥 Common redirect parameter names
    redirect_params = [
        "redirect", "url", "next", "return", "return_url", "continue"
    ]

    # 🔥 Payload variations (important!)
    payloads = [
        "https://evil.com",
        "//evil.com",              # bypass scheme validation
        "https:evil.com"           # malformed but sometimes works
    ]

    parsed_params = get_params(url)

    if not parsed_params:
        return findings

    for param in parsed_params:
        if param.lower() not in redirect_params:
            continue

        for payload in payloads:
            test_params = parsed_params.copy()
            test_params[param] = payload

            test_url = build_url(url, test_params)

            try:
                response = requests.get(
                    test_url,
                    allow_redirects=False,
                    timeout=5
                )

                location = response.headers.get("Location", "")

                # ✅ Check if redirect actually points to attacker domain
                if "evil.com" in location:
                    findings.append({
                        "type": "Open Redirect",
                        "severity": "Medium",
                        "parameter": param,
                        "payload": payload,
                        "url": test_url
                    })

            except requests.exceptions.RequestException:
                continue

    return findings