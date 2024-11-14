import re

def detect_sql_injection(input_str):
    sql_patterns = [r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE)\b)", r"' OR '1'='1"]
    for pattern in sql_patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            return True
    return False

def detect_xss(input_str):
    xss_patterns = [r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>"]
    for pattern in xss_patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            return True
    return False

def detect_lfi(input_str):
    lfi_patterns = [r"\.\./", r"/etc/passwd", r"\.\.\\", r"C:\\Windows"]
    for pattern in lfi_patterns:
        if re.search(pattern, input_str):
            return True
    return False

def detect_crlf_injection(input_str):
    crlf_patterns = [r"%0d%0a", r"\r\n"]
    for pattern in crlf_patterns:
        if re.search(pattern, input_str):
            return True
    return False
