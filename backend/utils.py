import os

log_file = 'scan_results.txt'

def load_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return []

def log_scan_result(url, payload, scan_type, indicator, result):
    with open(log_file, 'a') as f:
        f.write(f"URL: {url}, Payload: {payload}, Type: {scan_type}, Indicator: {indicator}, Vulnerable: {result}\n")
