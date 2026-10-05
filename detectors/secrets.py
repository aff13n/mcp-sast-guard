import math
import re
from typing import List, Dict, Any

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    entropy = 0.0
    length = len(s)
    occurrences: Dict[str, int] = {}
    for char in s:
        occurrences[char] = occurrences.get(char, 0) + 1
    for count in occurrences.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN.*PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[pous]_[A-Za-z0-9_]{36,255}"),
    "generic_api_key": re.compile(r"(?i)(?:key|token|secret|password|pwd|api_key|apikey)[\s=:\"\']+\s*([a-zA-Z0-9_\-\.]{32,})"),
}

def scan_secrets(text: str) -> List[Dict[str, Any]]:
    findings = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        line_num = i + 1
        
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(line):
                findings.append({
                    "type": secret_type,
                    "line": line_num,
                    "preview": match.group(0)[:20] + "..."
                })
        
        words = re.findall(r'[a-zA-Z0-9_\-\.]{32,}', line)
        for word in words:
            if shannon_entropy(word) > 4.5:
                is_duplicate = False
                for f in findings:
                    if f["line"] == line_num and word[:10] in f["preview"]:
                        is_duplicate = True
                        break
                if not is_duplicate:
                    findings.append({
                        "type": "high_entropy",
                        "line": line_num,
                        "preview": word[:20] + "..."
                    })
    return findings
