from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import requests
import os
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Define paths to payload and indicator files
sql_payloads_file = os.path.join(os.path.dirname(__file__), 'sql_payloads.txt')
cmd_payloads_file = os.path.join(os.path.dirname(__file__), 'command_payloads.txt')
indicators_file = os.path.join(os.path.dirname(__file__), 'command_indicator.txt')
log_file = os.path.join(os.path.dirname(__file__), 'scan_results.txt')
report_file = os.path.join(os.path.dirname(__file__), 'scan_report.txt')

# Email configuration
SMTP_SERVER = 'smtp.gmail.com'  # Replace with your SMTP server
SMTP_PORT = 587
EMAIL_USER = 'rohan91204@gmail.com'  # Replace with your email
EMAIL_PASSWORD = 'qqqqqqqqq'  # Replace with your email password

# Load payloads or indicators from a file
def load_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return []

# Log scan result to a file
def log_scan_result(url, payload, scan_type, indicator, result):
    with open(log_file, 'a') as f:
        f.write(f"URL: {url}, Payload: {payload}, Type: {scan_type}, Indicator: {indicator}, Vulnerable: {result}\n")

# Generate report file based on scan results
def generate_report(scan_details):
    with open(report_file, 'w') as f:
        f.write("Vulnerability Scan Report\n")
        f.write(f"URL: {scan_details['url']}\n")
        f.write(f"Scan Type: {scan_details['scan_type']}\n")
        f.write(f"Timestamp: {scan_details['timestamp']}\n")
        f.write(f"Vulnerable: {scan_details['vulnerable']}\n")
        if scan_details['vulnerable']:
            f.write(f"Payload: {scan_details['payload']}\n")
            f.write(f"Indicator: {scan_details['indicator']}\n")

# Email the report file
def send_email_with_report(to_email):
    try:
        msg = MIMEMultipart()
        msg['From'] = 'rohan91204@gmail.com'
        msg['To'] = 'rohan9120491204@gmail.com'
        msg['Subject'] = 'Vulnerability Scan Report'
        
        body = 'Please find attached the vulnerability scan report.'
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach the report file
        with open(report_file, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename=scan_report.txt')
            msg.attach(part)
        
        # Send the email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())
        server.quit()
        print("Report sent successfully.")
        return {"status": "success", "message": "Report sent successfully."}
    except Exception as e:
        print(f"Failed to send email: {e}")
        return {"status": "failure", "message": str(e)}

# SQL Injection scan
def check_sql_injection(url):
    payloads = load_file(sql_payloads_file)
    for payload in payloads:
        try:
            response = requests.get(url + payload)
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                log_scan_result(url, payload, "SQL Injection", "SQL Error", True)
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "indicator": "SQL Error"
                }
            else:
                log_scan_result(url, payload, "SQL Injection", "SQL Error", False)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            log_scan_result(url, payload, "SQL Injection", "Request Error", "Error")
    return {"vulnerable": False}

# Command Injection scan
def check_command_injection(url):
    payloads = load_file(cmd_payloads_file)
    indicators = load_file(indicators_file)
    
    for payload in payloads:
        try:
            response = requests.get(f"{url}{payload}")
            for indicator in indicators:
                if indicator.lower() in response.text.lower():
                    log_scan_result(url, payload, "Command Injection", indicator, True)
                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "indicator": indicator
                    }
            log_scan_result(url, payload, "Command Injection", "No Indicator", False)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            log_scan_result(url, payload, "Command Injection", "Request Error", "Error")
    return {"vulnerable": False}

# API to scan for vulnerabilities
@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')
    scan_type = data.get('scan_type')
    email = data.get('email')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    scan_details = {
        "url": url,
        "scan_type": scan_type,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    if scan_type == "sql_injection":
        result = check_sql_injection(url)
    elif scan_type == "command_injection":
        result = check_command_injection(url)
    else:
        return jsonify({"error": "Invalid scan type"}), 400

    # Combine general scan details with the result
    scan_details.update(result)
    
    # Generate report
    generate_report(scan_details)
    
    # Send report via email if email is provided
    if email:
        email_status = send_email_with_report(email)
        scan_details["email_status"] = email_status

    return jsonify(scan_details), 200

# Route to download the report
@app.route('/download_report', methods=['GET'])
def download_report():
    return send_file(report_file, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
