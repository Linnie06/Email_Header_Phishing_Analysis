import re
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def banner():
    print("\n======================================")
    print(" EMAIL HEADER PHISHING ANALYSIS TOOL")
    print("======================================\n")


def input_header():

    print("Paste Email Header Below")
    print("Type END on a new line to finish\n")

    lines = []

    while True:
        try:
            line = input()

            if line.strip().upper() == "END":
                break

            lines.append(line)

        except EOFError:
            break

    return "\n".join(lines)


def parse_header(header):

    data = {}

    data['from'] = re.search(r"From:.*", header, re.IGNORECASE)
    data['return_path'] = re.search(r"Return-Path:.*", header, re.IGNORECASE)
    data['reply_to'] = re.search(r"Reply-To:.*", header, re.IGNORECASE)

    data['subject'] = re.search(r"Subject:.*", header, re.IGNORECASE)
    data['date'] = re.search(r"Date:.*", header, re.IGNORECASE)

    data['message_id'] = re.search(
        r"Message[- ]ID:.*",
        header,
        re.IGNORECASE)
    data['x_mailer'] = re.search(r"X-Mailer:.*", header, re.IGNORECASE)

    data['spf'] = re.search(
        r"\bspf[:=]\s*'?(\w+)",
        header,
        re.IGNORECASE)

    data['dkim'] = re.search(
        r"dkim[:=]\s*'?(\w+)",
        header,
        re.IGNORECASE)

    data['dmarc'] = re.search(
        r"dmarc[:=]\s*'?(\w+)",
        header,
        re.IGNORECASE)

    data['spf_domain'] = re.search(
        r"smtp\.mailfrom=([\w.-]+)",
        header,
        re.IGNORECASE)

    data['dkim_domain'] = re.search(
        r"header\.d=([\w.-]+)",
        header,
        re.IGNORECASE)

    data['received'] = re.findall(
        r"^Received:.*",
        header,
        re.IGNORECASE | re.MULTILINE)

    data['ips'] = re.findall(
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        header)

    return data


def extract_domain(line):

    if line is None:
        return None

    match = re.search(
        r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        line)

    if match:
        return match.group(1).lower()

    return None


def show_parsed(parsed):

    print("\nExtracted Header Information\n")

    for key in parsed:

        value = parsed[key]

        if value:

            if isinstance(value, list):
                print(key.upper(), ":", len(value))

            else:
                try:
                    print(key.upper(), ":", value.group())
                except:
                    print(key.upper(), ":", value)


def extract_features(data):

    features = {

        "from_return_mismatch": False,
        "replyto_mismatch": False,
        "auth_domain_mismatch": False,

        "spf_fail": False,
        "dkim_fail": False,
        "dmarc_fail": False,

        "missing_authentication": False,

        "missing_messageid": False,
        "missing_replyto": False,

        "few_servers": False,
        "many_servers": False,

        "suspicious_domain": False,
        "numeric_domain": False,
        "short_domain": False,

        "suspicious_mailer": False,
        "suspicious_messageid": False,

        "many_ips": False,

        "softfail_spf": False
    }

    from_domain = extract_domain(
        data['from'].group()) if data['from'] else None

    return_domain = extract_domain(
        data['return_path'].group()) if data['return_path'] else None

    reply_domain = extract_domain(
        data['reply_to'].group()) if data['reply_to'] else None
    if not data['reply_to']:
        features["missing_replyto"] = True

    if from_domain and return_domain:
        if from_domain != return_domain:
            features["from_return_mismatch"] = True

    if from_domain and reply_domain:
        if from_domain != reply_domain:
            features["replyto_mismatch"] = True

    spf_domain = data['spf_domain'].group(1) if data['spf_domain'] else None
    dkim_domain = data['dkim_domain'].group(1) if data['dkim_domain'] else None

    if from_domain:

        if spf_domain and from_domain not in spf_domain:
            features["auth_domain_mismatch"] = True

        if dkim_domain and from_domain not in dkim_domain:
            features["auth_domain_mismatch"] = True

    if data['spf']:

        value = data['spf'].group(1).lower()

        if value == "fail":
            features["spf_fail"] = True

        if value == "softfail":
            features["softfail_spf"] = True

    if data['dkim']:
        if data['dkim'].group(1).lower() == "fail":
            features["dkim_fail"] = True

    if data['dmarc']:
        if data['dmarc'].group(1).lower() == "fail":
            features["dmarc_fail"] = True

    if not data['spf'] and not data['dkim'] and not data['dmarc']:
        features["missing_authentication"] = True

    if len(data['received']) <= 1 and len(data['received']) != 0:
        features["few_servers"] = True

    if len(data['received']) > 8:
        features["many_servers"] = True

    suspicious_words = [
        "paypa1",
        "amaz0n",
        "micr0soft",
        "secure",
        "verify",
        "login",
        "bank"
    ]

    if from_domain:

        for word in suspicious_words:
            if word in from_domain:
                features["suspicious_domain"] = True

        if re.search(r"\d\d\d", from_domain):
            features["numeric_domain"] = True

        if len(from_domain) < 6:
            features["short_domain"] = True

    if not data['message_id']:
        features["missing_messageid"] = True

    if data['message_id'] and from_domain:

        msg_domain = extract_domain(data['message_id'].group())

        if msg_domain and msg_domain != from_domain:
            features["suspicious_messageid"] = True

    if data['x_mailer']:

        mailer = data['x_mailer'].group().lower()

        if "python" in mailer or "php" in mailer or "bot" in mailer:
            features["suspicious_mailer"] = True

    if len(data['ips']) > 6:
        features["many_ips"] = True

    return features


def detect_phishing(features):

    if (
        not features["spf_fail"]
        and not features["dkim_fail"]
        and not features["dmarc_fail"]
        and not features["missing_authentication"]
        and not features["from_return_mismatch"]
    ):
        return "LIKELY LEGITIMATE (STRONG AUTHENTICATION)", 0

    weights = {

        "from_return_mismatch": 4,
        "replyto_mismatch": 3,
        "auth_domain_mismatch": 4,

        "spf_fail": 5,
        "dkim_fail": 5,
        "dmarc_fail": 5,

        "missing_authentication": 4,

        "missing_messageid": 2,
        "missing_replyto": 1,

        "few_servers": 2,
        "many_servers": 1,

        "suspicious_domain": 4,
        "numeric_domain": 2,
        "short_domain": 1,

        "suspicious_mailer": 3,
        "suspicious_messageid": 3,

        "many_ips": 2,

        "softfail_spf": 2
    }

    score = 0

    for k in features:
        if features[k]:
            score += weights[k]

    if score >= 15:
        result = "HIGH RISK PHISHING EMAIL"

    elif score >= 7:
        result = "SUSPICIOUS EMAIL"

    else:
        result = "LIKELY LEGITIMATE EMAIL"

    return result, score

@app.route("/")
def home():
    return "Email Header Phishing Analysis Tool is Running"

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data or "header" not in data:
        return jsonify({"error": "No header provided"}), 400

    header = data["header"]

    parsed = parse_header(header)

    features = extract_features(parsed)

    result, score = detect_phishing(features)

    if len(parsed['received']) == 0:
        warning = "WARNING: Header appears incomplete. Use FULL header (Show Original)."
    else:
        warning = ""

    return jsonify({
        "result": result,
        "score": score,
        "features": features,
        "warning": warning
    })

if __name__ == "__main__":
    app.run()