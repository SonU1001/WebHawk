import argparse
import sys
from colorama import Fore, Style, init

from modules import (
    xss_scanner,
    sqli_scanner,
    cors_checker,
    open_redirect,
    headers_checker,
    reporter
)

init(autoreset=True)


# -------------------- UI -------------------- #

def print_banner():
    print(Fore.CYAN + Style.BRIGHT + """
██╗    ██╗███████╗██████╗ ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
██║    ██║██╔════╝██╔══██╗██║  ██║██╔══██╗██║    ██║██║ ██╔╝
██║ █╗ ██║█████╗  ██████╔╝███████║███████║██║ █╗ ██║█████╔╝ 
██║███╗██║██╔══╝  ██╔══██╗██╔══██║██╔══██║██║███╗██║██╔═██╗ 
╚███╔███╔╝███████╗██████╔╝██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
""")


def print_error(message):
    print(Fore.RED + f"[!] Error: {message}")


def print_info(message):
    print(Fore.CYAN + f"[*] {message}")


def print_success(message):
    print(Fore.GREEN + f"[✔] {message}")


# -------------------- VALIDATION -------------------- #

def validate_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return False
    return True


# -------------------- SCAN ENGINE -------------------- #

def run_scans(target):
    results = []

    scanners = [
        ("XSS Scanner", xss_scanner.scan_xss),
        ("SQL Injection Scanner", sqli_scanner.scan_sqli),
        ("CORS Checker", cors_checker.check_cors),
        ("Open Redirect Scanner", open_redirect.check_redirect),
        ("Security Headers Checker", headers_checker.check_headers),
    ]

    for name, scanner_func in scanners:
        print_info(f"Running {name}...")

        try:
            findings = scanner_func(target)
            if findings:
                results.extend(findings)
        except Exception as e:
            print_error(f"{name} failed: {str(e)}")

    return results


# -------------------- OUTPUT -------------------- #

def print_summary(results):
    summary = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}

    for r in results:
        sev = r.get("severity", "Info")
        if sev in summary:
            summary[sev] += 1

    print(Fore.MAGENTA + "\n[+] Summary")
    print(Fore.RED + f"    High   : {summary['High']}")
    print(Fore.YELLOW + f"    Medium : {summary['Medium']}")
    print(Fore.GREEN + f"    Low    : {summary['Low']}")
    print(Fore.CYAN + f"    Info   : {summary['Info']}")
    print("-" * 60)


def print_results(results):
    if not results:
        print_success("No vulnerabilities found.")
        return

    print(Fore.MAGENTA + "\n[+] Detailed Findings\n")

    for i, item in enumerate(results, 1):
        severity = item.get("severity", "Info").lower()

        color_map = {
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.GREEN,
            "info": Fore.CYAN
        }

        color = color_map.get(severity, Fore.CYAN)

        print(color + Style.BRIGHT + f"[{i}] {item.get('type')}")
        print(Style.DIM + f"    Severity : {item.get('severity')}")
        print(Style.DIM + f"    URL      : {item.get('url')}")

        if item.get("parameter"):
            print(Style.DIM + f"    Parameter: {item.get('parameter')}")

        if item.get("payload"):
            print(Style.DIM + f"    Payload  : {item.get('payload')}")

        if item.get("description"):
            print(Style.DIM + f"    Info     : {item.get('description')}")

        if item.get("details"):
            print(Style.DIM + f"    Details  : {item.get('details')}")

        print("-" * 60)


# -------------------- MAIN -------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="WebHawk - Automated Web Vulnerability Scanner"
    )

    parser.add_argument(
        "url",
        help="Target URL (must include http:// or https://)"
    )

    parser.add_argument(
        "--html",
        action="store_true",
        help="Output results to HTML file only"
    )

    args = parser.parse_args()
    target = args.url

    print_banner()

    # Validate URL
    if not validate_url(target):
        print_error("Invalid URL. Must start with http:// or https://")
        sys.exit(1)

    print(Fore.YELLOW + f"[+] Target: {target}\n")

    # Run scans
    results = run_scans(target)

    print_success(f"Scan Completed. Total Findings: {len(results)}")

    # Output handling
    if args.html:
        try:
            reporter.generate_report(target, results)
            print(Fore.MAGENTA + "[+] HTML report saved as report.html")
        except Exception as e:
            print_error(f"Failed to generate report: {str(e)}")
    else:
        print_summary(results)
        print_results(results)


if __name__ == "__main__":
    main()