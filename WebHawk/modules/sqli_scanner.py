import requests
import urllib.parse

def get_params(url):
    """
    Extract parameters from URL
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


def is_different(response1, response2):
    """
    Compare responses to detect behavioral changes
    """
    return response1.text != response2.text


def scan_sqli(url):
    findings = []

    # 🔥 Error-based payloads
    error_payloads = [
        "'",
        "\"",
        "'--",
        "' OR '1'='1",
        "' OR '1'='2"
    ]

    # 🔥 SQL error signatures
    sql_errors = [
        "sql syntax",
        "mysql",
        "warning",
        "unterminated",
        "odbc",
        "pdo",
        "query failed"
    ]

    params = get_params(url)

    if not params:
        return findings

    try:
        baseline_response = requests.get(url, timeout=5)
    except:
        return findings

    for param in params:
        original_value = params[param][0]

        # --- Error-based detection ---
        for payload in error_payloads:
            test_params = params.copy()
            test_params[param] = payload

            test_url = build_url(url, test_params)

            try:
                response = requests.get(test_url, timeout=5)

                for error in sql_errors:
                    if error in response.text.lower():
                        findings.append({
                            "type": "SQL Injection (Error-Based)",
                            "severity": "High",
                            "parameter": param,
                            "payload": payload,
                            "url": test_url
                        })
                        break

            except requests.exceptions.RequestException:
                continue

        # --- Boolean-based detection (VERY IMPORTANT) ---
        true_payload = "' OR '1'='1"
        false_payload = "' OR '1'='2"

        try:
            true_params = params.copy()
            false_params = params.copy()

            true_params[param] = true_payload
            false_params[param] = false_payload

            true_url = build_url(url, true_params)
            false_url = build_url(url, false_params)

            res_true = requests.get(true_url, timeout=5)
            res_false = requests.get(false_url, timeout=5)

            # ✅ Compare behavior difference
            if is_different(res_true, res_false):
                findings.append({
                    "type": "SQL Injection (Boolean-Based)",
                    "severity": "High",
                    "parameter": param,
                    "payload": f"{true_payload} / {false_payload}",
                    "url": true_url
                })

        except requests.exceptions.RequestException:
            continue

    return findings