from datetime import datetime

def generate_report(target, findings):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""
    <html>
    <head>
        <title>WebHawk Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #0d1117;
                color: #c9d1d9;
                margin: 0;
                padding: 20px;
            }}
            h1 {{
                color: #58a6ff;
            }}
            .container {{
                max-width: 1000px;
                margin: auto;
            }}
            .card {{
                background: #161b22;
                padding: 15px;
                margin-bottom: 15px;
                border-radius: 8px;
                border-left: 5px solid;
            }}
            .high {{ border-color: #f85149; }}
            .medium {{ border-color: #d29922; }}
            .low {{ border-color: #3fb950; }}
            .info {{ border-color: #58a6ff; }}

            .badge {{
                padding: 4px 8px;
                border-radius: 5px;
                font-size: 12px;
                font-weight: bold;
            }}
            .badge-high {{ background: #f85149; }}
            .badge-medium {{ background: #d29922; }}
            .badge-low {{ background: #3fb950; }}
            .badge-info {{ background: #58a6ff; }}

            .meta {{
                font-size: 14px;
                margin-bottom: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🦅 WebHawk Scan Report</h1>
            <div class="meta">
                <p><b>Target:</b> {target}</p>
                <p><b>Scan Time:</b> {now}</p>
                <p><b>Total Findings:</b> {len(findings)}</p>
            </div>
            <hr>
    """

    if not findings:
        html += "<p>No vulnerabilities found.</p>"
    else:
        for item in findings:
            severity = item.get("severity", "info").lower()

            html += f"""
            <div class="card {severity}">
                <h3>{item.get('type')}</h3>
                <span class="badge badge-{severity}">
                    {item.get('severity')}
                </span>
                <p><b>URL:</b> {item.get('url')}</p>
            """

            if "parameter" in item:
                html += f"<p><b>Parameter:</b> {item.get('parameter')}</p>"

            if "payload" in item:
                html += f"<p><b>Payload:</b> {item.get('payload')}</p>"

            if "description" in item:
                html += f"<p><b>Description:</b> {item.get('description')}</p>"

            if "details" in item:
                html += f"<p><b>Details:</b> {item.get('details')}</p>"

            html += "</div>"

    html += """
        </div>
    </body>
    </html>
    """

    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)