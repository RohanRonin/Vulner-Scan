from flask import Flask, jsonify, request
from flask_cors import CORS
from sql_scanner import check_sql_injection
from command_scanner import check_command_injection
from xss_scanner import scan_for_xss

app = Flask(__name__)

# Enable CORS for all routes and origins, allowing your React app on localhost:3000 to connect
CORS(app, origins=["http://localhost:3000"])

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get("url")
    scan_type = data.get("scan_type")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    if scan_type == "sql_injection":
        result = check_sql_injection(url)
    elif scan_type == "command_injection":
        result = check_command_injection(url)
    elif scan_type == "xss":
        result = scan_for_xss(url)
    else:
        return jsonify({"error": "Invalid scan type"}), 400

    return jsonify(result), 200

if __name__ == '__main__':
    app.run(debug=True)
