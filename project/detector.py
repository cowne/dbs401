import sqlparse
from sqlparse.sql import Where, Comparison
from sqlparse.tokens import Keyword, DML, Whitespace, Literal
import re
import urllib.parse
import codecs
import db
import os
import csv
from datetime import datetime


def preprocess_query(query: str) -> bool:
    # Step 1: URL-decode
    decoded = urllib.parse.unquote_plus(query)

    # Step 2: Decode hex strings (e.g., 0x61646D696E → admin)
    def hex_to_ascii(match):
        hex_str = match.group(0)
        try:
            bytes_str = bytes.fromhex(hex_str[2:])  # remove "0x"
            return bytes_str.decode('utf-8', errors='replace')
        except Exception:
            return hex_str  # return original if decode fails

    decoded = re.sub(r'0x[0-9a-fA-F]+', hex_to_ascii, decoded)

    # Step 3: Decode Unicode escapes (e.g., \u0061 → a)
    try:
        decoded = codecs.decode(decoded, 'unicode_escape')
    except Exception:
        pass  # if decoding fails, skip

    # Step 4: Normalize whitespace and case
    decoded = re.sub(r'\s+', ' ', decoded)
    return decoded.upper()

def normalize(val: str) -> str:
    val = val.strip().lower()
    if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
        val = val[1:-1]
    return val

def detect_tautology_with_sqlparse(query: str) -> bool:

    query = re.split(r'--|#', query)[0]

    parsed = sqlparse.parse(query)
    if not parsed:
        return False

    stmt = parsed[0]
    
    # Tìm phần WHERE
    where_clause = None
    for token in stmt.tokens:
        if isinstance(token, Where):
            where_clause = token
            break
    
    if not where_clause:
        return False

    tokens = where_clause.tokens
    for i in range(len(tokens)):
        token = tokens[i]
        # Tìm OR / AND
        if token.ttype is Keyword and token.value.upper() in ("OR", "AND"):
            # Tìm biểu thức sau OR/AND
            for j in range(i + 1, len(tokens)):
                next_token = tokens[j]
                if isinstance(next_token, Comparison):
                    # Lấy trái/phải dấu =
                    parts = [t.value.strip() for t in next_token.tokens if t.ttype != Whitespace]
                    if len(parts) == 3 and parts[1] == '=':
                        left = normalize(parts[0])
                        right = normalize(parts[2])
                        # left = parts[0]
                        # right = parts[2]
                        #print(left, right)
                        if left == right:
                            print(f"[!] Detected tautology: {left} = {right} (after {token.value.upper()})")
                            return True
                elif next_token.ttype in (Literal.Number.Integer, Keyword) and normalize(next_token.value) in ("1", "0", "true", "false"):
                    print(f"[!] Detected literal tautology: {next_token.value} (after {token.value.upper()})")
                    return True
    return False

def detect_stack_queries(query: str) -> bool:
    parsed = sqlparse.parse(query)
    if len(parsed) > 1:
        return True
    return False

def detect_union_attack(query: str) -> bool:
    pattern = r"UNION(\s+ALL|\s+DISTINCT)?\s+SELECT"
    return re.search(pattern, query, re.IGNORECASE) is not None

def detect_time_based_attack(query: str) -> bool:
    pattern = r'\b(SLEEP|BENCHMARK)\b\s*\('
    return re.search(pattern, query, re.IGNORECASE) is not None

def detect_error_based_attack(query: str) -> bool:
    error_functions = [
        r'\bUPDATEXML\s*\(',      # Triggers XML parsing error
        r'\bEXTRACTVALUE\s*\(',   # Triggers XML error
        r'\bCONVERT\s*\(',        # Can trigger data type conversion errors
        r'\bCAST\s*\(',           # Cast errors (e.g., CAST('a' AS DECIMAL))
        r'\bGTID_SUBSET\s*\(',
        r'\bJSON_KEYS\s*\(',
        r'\bEXP\s*\(',
        r'\bNAME_CONST\s*\(',
        r'\bUUID_TO_BIN\s*\(',
        r'\bCAST\s*\(',
    ]

    error_patterns = [
        r'1\s*/\s*0',             # Division by zero
        r'CHAR\s*\(\s*[0-9]{5,}', # Large CHAR codes can trigger errors
    ]

    patterns = error_patterns + error_functions

    for pattern in patterns:
        if re.search(pattern, query):
            return True
    return False

def check_exploit_sqli(query: str) -> bool:
    q = preprocess_query(query)
    if detect_tautology_with_sqlparse(q):
        write_attack_log(query, "SQL Injection (Tautology)")
        return True
    if detect_stack_queries(q):
        write_attack_log(query, "SQL Injection (Stacked Queries)")
        return True
    if detect_union_attack(q):
        write_attack_log(query, "SQL Injection (UNION Queries)")
        return True
    if detect_error_based_attack(q):
        write_attack_log(query, "SQL Injection (Error-Based)")
        return True
    if detect_time_based_attack(q):
        write_attack_log(query, "SQL Injection (Time-Based)")
    return False

def get_results(query: str):
    return db.run_query(query)


def write_attack_log(query: str, attack_type: str):
    """
    Writes an attack log entry to 'attack_detected.csv'.

    If the file does not exist, it will be created with headers.
    Each entry includes the current datetime, the detected payload (query),
    and the type of attack.

    Args:
        query (str): The suspicious query or payload detected.
        attack_type (str): The type of attack detected (e.g., 'SQL Injection', 'XSS').
    """
    filename = "attack_detected_logs.csv"
    headers = ["datetime", "payload", "type"]
    file_exists = os.path.exists(filename)

    # Get the current datetime in a human-readable format
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        # Open the file in append mode. If it doesn't exist, it will be created.
        with open(filename, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)

            # If the file is new, write the header row
            if not file_exists:
                writer.writerow(headers)

            # Write the data row
            writer.writerow([current_datetime, query, attack_type])

        print(f"Attack log entry written to '{filename}': Datetime='{current_datetime}', Payload='{query}', Type='{attack_type}'")

    except IOError as e:
        print(f"Error writing to file '{filename}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

#check authentication, nếu mà admin thì sẽ cho chạy những function nguy hiểm, người dùng bình thường thì sẽ chặn những người dùng bth
#sửa cái proxy thành một cái server, query sẽ chạy qua proxy kiểm tra rồi check, nếu oke thì thực thi, không thì chặn (ưu tiên cái này trước)