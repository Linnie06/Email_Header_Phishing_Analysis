# Email_Header_Phishing_Analysis

A lightweight phishing detection tool that analyzes raw email headers for suspicious indicators using Python, Flask, and a simple frontend interface.

This project helps identify potentially malicious or spoofed emails by checking:

* SPF, DKIM, and DMARC authentication results
* Domain mismatches
* Suspicious sender patterns
* Missing or forged email metadata
* Server routing inconsistencies
* Suspicious mailers and message IDs

The application provides a phishing risk classification along with a calculated risk score and detected indicators.

---

# Features

## Email Header Parsing

The backend extracts important email header information such as:

* From
* Return-Path
* Reply-To
* Subject
* Date
* Message-ID
* X-Mailer
* SPF
* DKIM
* DMARC
* Received servers
* IP addresses

---

## Phishing Detection Indicators

The tool detects multiple phishing-related indicators including:

### Domain & Identity Checks

* From vs Return-Path mismatch
* Reply-To mismatch
* Authentication domain mismatch
* Suspicious domains
* Numeric domains
* Extremely short domains

### Authentication Checks

* SPF failure
* SPF softfail
* DKIM failure
* DMARC failure
* Missing authentication records

### Structural Email Checks

* Missing Message-ID
* Missing Reply-To
* Suspicious Message-ID
* Suspicious X-Mailer
* Too few or too many mail servers
* Excessive IP addresses

---

# Risk Classification

The system assigns a weighted score to suspicious indicators.

| Score Range | Classification           |
| ----------- | ------------------------ |
| 0–6         | Likely Legitimate Email  |
| 7–14        | Suspicious Email         |
| 15+         | High Risk Phishing Email |

If strong authentication passes without major mismatches, the email is classified as:

`LIKELY LEGITIMATE (STRONG AUTHENTICATION)`

---

# Tech Stack

## Backend

* Python
* Flask
* Flask-CORS
* Regular Expressions (re)

## Frontend

* HTML
* CSS
* JavaScript

---

# Project Structure

```bash
Project/
│
├── app.py
├── index.html
├── style.css
├── script.js
└── phishing_report.txt
```

---

# Installation

## 1. Clone the Repository

```bash
git clone https://github.com/Linnie06/Email_Header_Phishing_Analysis.git
cd Email_Header_Phishing_Analysis
```

---

## 2. Install Dependencies

```bash
pip install flask flask-cors
```

---

# Running the Application

## Start the Flask Backend

```bash
python app.py
```

The server will start at:

```bash
http://127.0.0.1:5000
```

---

## Open the Frontend

Open `index.html` in your browser.

Paste a full email header into the text area and click:

```text
Analyze Header
```

---

# API Endpoint

## POST /analyze

Analyzes an email header and returns phishing indicators.

### Request

```json
{
  "header": "raw email header here"
}
```

### Response

```json
{
  "result": "HIGH RISK PHISHING EMAIL",
  "score": 18,
  "features": {
    "spf_fail": true,
    "dkim_fail": true,
    "from_return_mismatch": true
  },
  "warning": ""
}
```

---

# Example Workflow

1. Copy the full email header from an email client.
2. Paste the header into the application.
3. Run the analysis.
4. Review:

   * Risk score
   * Classification
   * Triggered phishing indicators
   * Warning messages

---

# Future Improvements

Possible enhancements for the project:

* WHOIS domain reputation checks
* Blacklist/IP reputation integration
* Machine learning phishing classification
* Geo-location analysis for IP addresses
* PDF report generation
* Email attachment scanning
* URL extraction and sandbox analysis
* Real-time threat intelligence integration
* Dark mode UI
* Database logging for analyzed emails

---

# Learning Objectives

This project demonstrates:

* Email header analysis
* Cybersecurity threat detection basics
* Flask API development
* Frontend-backend integration
* Rule-based phishing detection
* Regex-based parsing techniques

---

# Disclaimer

This tool provides heuristic-based phishing analysis and should not be considered a replacement for enterprise email security solutions.

False positives and false negatives are possible.

---

# Author

Created as a cybersecurity project focused on email phishing detection and email header analysis.
