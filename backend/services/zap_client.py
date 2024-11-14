import requests

ZAP_URL = "http://localhost:8080"  # Local ZAP instance

def run_zap_scan(target_url):
    try:
        # Initiate a scan in ZAP
        scan_response = requests.get(f"{ZAP_URL}/JSON/ascan/action/scan/", params={"url": target_url})
        return scan_response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
