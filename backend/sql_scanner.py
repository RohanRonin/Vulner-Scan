import requests
from utils import load_file, log_scan_result

sql_payloads_file = 'sql_payloads.txt'

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
