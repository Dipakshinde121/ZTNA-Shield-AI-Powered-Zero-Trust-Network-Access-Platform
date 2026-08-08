import math
import re

# Compiled regex patterns for keyword counting
SQL_KEYWORDS = re.compile(
    r"\b(select|union|insert|update|delete|drop|alter|where|from|having|group\s+by|order\s+by|exec|execute|declare|cast|convert)\b",
    re.IGNORECASE
)

XSS_KEYWORDS = re.compile(
    r"(<script|javascript:|onload=|onerror=|onclick=|onmouseover=|alert\(|confirm\(|prompt\(|eval\(|document\.cookie|document\.location|window\.location|svg/onload|<iframe|<img|<body|<html|<svg)",
    re.IGNORECASE
)

CMD_KEYWORDS = re.compile(
    r"\b(whoami|id|uname|wget|curl|nc|netcat|nmap|bash|sh|cmd\.exe|powershell|etc/passwd|etc/hosts|bin/sh|bin/bash|system\(|exec\(|passthru\(|popen\()\b",
    re.IGNORECASE
)

ENCODING_PATTERNS = re.compile(
    r"(%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|u00[0-9a-fA-F]{2}|base64|dbms_|union\s+select)",
    re.IGNORECASE
)

def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string (measures randomness/obfuscation)."""
    if not s:
        return 0.0
    
    entropy = 0.0
    len_s = len(s)
    # Calculate frequencies of characters
    frequencies = {}
    for char in s:
        frequencies[char] = frequencies.get(char, 0) + 1
        
    for count in frequencies.values():
        p = count / len_s
        entropy -= p * math.log2(p)
        
    return entropy

def extract_features(payload: str) -> list[float]:
    """
    Transforms a raw payload string into a 10-dimensional numeric feature vector.
    
    Features list:
    1. Log-scaled length of payload
    2. Shannon entropy (0.0 to 8.0)
    3. Special character ratio (non-alphanumeric chars / total length)
    4. Digit ratio (digit chars / total length)
    5. SQL keyword matches count
    6. XSS keyword matches count
    7. System/Command keyword matches count
    8. Encoding artifact matches count (URL/Hex encodings)
    9. Uppercase ratio (uppercase letters / total letters)
    10. Null byte / whitespace ratio
    """
    if not payload:
        return [0.0] * 10
        
    length = len(payload)
    
    # 1. Length feature (log scaled to handle large payloads smoothly)
    f_length = math.log1p(length)
    
    # 2. Entropy
    f_entropy = shannon_entropy(payload)
    
    # 3. Special characters ratio
    special_chars = len(re.sub(r'[a-zA-Z0-9\s]', '', payload))
    f_special_ratio = special_chars / length
    
    # 4. Digit ratio
    digits = len(re.sub(r'[^0-9]', '', payload))
    f_digit_ratio = digits / length
    
    # 5-8. Keyword counts
    f_sql_count = len(SQL_KEYWORDS.findall(payload))
    f_xss_count = len(XSS_KEYWORDS.findall(payload))
    f_cmd_count = len(CMD_KEYWORDS.findall(payload))
    f_encoding_count = len(ENCODING_PATTERNS.findall(payload))
    
    # 9. Uppercase ratio
    letters = re.sub(r'[^a-zA-Z]', '', payload)
    if letters:
        f_uppercase_ratio = len(re.sub(r'[^A-Z]', '', letters)) / len(letters)
    else:
        f_uppercase_ratio = 0.0
        
    # 10. Null bytes and whitespace ratio
    spaces_and_nulls = len(re.findall(r'[\s\x00]', payload))
    f_space_ratio = spaces_and_nulls / length
    
    return [
        f_length,
        f_entropy,
        f_special_ratio,
        f_digit_ratio,
        float(f_sql_count),
        float(f_xss_count),
        float(f_cmd_count),
        float(f_encoding_count),
        f_uppercase_ratio,
        f_space_ratio
    ]

# Feature names mapping for logs/debugging
FEATURE_NAMES = [
    "log_length",
    "entropy",
    "special_char_ratio",
    "digit_ratio",
    "sql_keyword_count",
    "xss_keyword_count",
    "cmd_keyword_count",
    "encoding_count",
    "uppercase_ratio",
    "space_ratio"
]
