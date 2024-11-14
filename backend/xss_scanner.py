import requests
from bs4 import BeautifulSoup
from utils import load_file

xss_payloads_file = 'xss_payloads.txt'

def find_input_fields(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        inputs = soup.find_all("input", {"type": ["text", "search", "url", "email"]})
        return inputs
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return []

def scan_for_xss(url):
    findings = {"url": url, "vulnerabilities": []}
    input_fields = find_input_fields(url)
    payloads = load_file(xss_payloads_file)
    
    for input_field in input_fields:
        input_name = input_field.get("name")
        if not input_name:
            continue
        for payload in payloads:
            data = {input_name: payload}
            try:
                response = requests.get(url, params=data)
                if payload in response.text:
                    findings["vulnerabilities"].append({
                        "input_field": input_name,
                        "payload": payload,
                        "response_snippet": response.text[:500]
                    })
                    break
            except requests.RequestException as e:
                print(f"Error injecting payload {payload} in {input_name}: {e}")
    return findings
