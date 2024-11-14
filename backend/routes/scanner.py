from flask import Blueprint, jsonify, request
import requests
from utils.scanner import detect_sql_injection, detect_xss, detect_lfi, detect_crlf_injection

scanner_bp = Blueprint('scanner', __name__)

OWASP_ZAP_API = 'http://zap:8080'

@scanner_bp.route('/start_scan', methods=['POST'])
def start_scan():
    url = request.json.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Pre-scan checks
    if detect_sql_injection(url):
        return jsonify({"error": "Potential SQL Injection detected"}), 400
    if detect_xss(url):
        return jsonify({"error": "Potential XSS vulnerability detected"}), 400
    if detect_lfi(url):
        return jsonify({"error": "Potential Local File Inclusion detected"}), 400
    if detect_crlf_injection(url):
        return jsonify({"error": "Potential CRLF Injection detected"}), 400

    # Continue with OWASP ZAP scan
    zap_response = requests.get(f"{OWASP_ZAP_API}/JSON/ascan/action/scan/?url={url}")
    scan_id = zap_response.json().get("scan")

    return jsonify({"message": "Scan started", "scan_id": scan_id}), 200


@scanner_bp.route('/scan_results/<scan_id>', methods=['GET'])
def scan_results(scan_id):
    zap_results = requests.get(f"{OWASP_ZAP_API}/JSON/ascan/view/status/?scanId={scan_id}")
    status = zap_results.json().get("status")

    if status == "100":
        alerts_response = requests.get(f"{OWASP_ZAP_API}/JSON/core/view/alerts/")
        return jsonify({"status": "completed", "alerts": alerts_response.json()}), 200
    return jsonify({"status": "in_progress"}), 202
