# 🦅 WebHawk - Automated Web Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/Status-Active-success)
![License](https://img.shields.io/badge/License-Educational-red)

---

## 🔥 Overview

WebHawk is a modular Python-based web vulnerability scanner designed for **authorized penetration testing**. It detects common web vulnerabilities and provides results via CLI or HTML reports.

---

## 🚀 Features

* 🔍 Reflected XSS Detection (multi-payload)
* 💉 SQL Injection Detection (error + boolean-based)
* 🌍 CORS Misconfiguration Detection
* 🔁 Open Redirect Detection
* 🛡️ Security Headers Analysis
* 🎨 Beautiful CLI output
* 📄 Optional HTML reporting

---

## 📁 Project Structure

```
WebHawk/
│── main.py
│── requirements.txt
│── modules/
│    ├── xss_scanner.py
│    ├── sqli_scanner.py
│    ├── cors_checker.py
│    ├── open_redirect.py
│    ├── headers_checker.py
│    ├── reporter.py
```

---

## ⚙️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/WebHawk.git
cd WebHawk
pip install -r requirements.txt
```

---

## ▶️ Usage

### CLI Output

```bash
python main.py "http://target.com?id=1"
```

### HTML Report

```bash
python main.py "http://target.com?id=1" --html
```

---

## 🧪 Testing

Use safe targets:

* OWASP Juice Shop
* DVWA

---

## 📸 Screenshots

> Add screenshots of:
>
> * Terminal output
> * HTML report

---

## ⚠️ Disclaimer

This tool is strictly for **authorized testing only**.
Do not scan systems without permission.

---

## 🚀 Future Improvements

* Multi-threading
* Crawling support
* Payload wordlists
* JSON output

---

## 👨‍💻 Author

Sukhveer Singh
Cybersecurity Learner |

---
