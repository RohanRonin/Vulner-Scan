import requests
from utils import load_file, log_scan_result

cmd_payloads_file = 'command_payloads.txt'
indicators_file = 'command_indicator.txt'

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
