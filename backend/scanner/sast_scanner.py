"""
Static Application Security Testing (SAST) Scanner Module
"""
import re
from typing import List, Dict, Any

class SASTScanner:
    """Static Code Analyzer for Python and JavaScript/TypeScript"""
    
    def __init__(self):
        # Patterns for secrets
        self.secret_patterns = {
            "Generic Secret/API Key": r"(?:key|secret|token|password|passwd|auth|api_key|private_key)\s*=\s*['\"][A-Za-z0-9/\+=_\-]{16,}['\"]",
            "AWS Client ID/Secret": r"(?:AKIA[0-9A-Z]{16})|(?:[a-zA-Z0-9/+=]{40})",
            "Private Key Block": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"
        }
        
        # Python specific patterns
        self.py_patterns = [
            {
                "type": "SQL Injection Risk",
                "severity": "HIGH",
                "pattern": r"\.execute\(\s*f?['\"].*?\{.*?\}['\"].*?\)",
                "description": "SQL query built using f-strings or string concatenation. Use parameterized queries instead.",
                "remediation": "Replace with parameterized query: connection.execute('SELECT * FROM table WHERE id = %s', (id_val,))",
                "cwe_id": "CWE-89"
            },
            {
                "type": "SQL Injection Risk (Legacy Formatting)",
                "severity": "HIGH",
                "pattern": r"\.execute\(\s*['\"].*?%['\"]\s*%.*?\)",
                "description": "SQL query built using old-style (%) string formatting. Use parameterized queries instead.",
                "remediation": "Replace with parameterized query: connection.execute('SELECT * FROM table WHERE id = %s', (id_val,))",
                "cwe_id": "CWE-89"
            },
            {
                "type": "Unsafe Shell Command",
                "severity": "CRITICAL",
                "pattern": r"(?:subprocess\.(?:Popen|run|call|check_output)|os\.system)\(.*shell\s*=\s*True.*\)",
                "description": "Running subprocess with shell=True or using os.system. This risks command injection if user inputs are passed.",
                "remediation": "Avoid shell=True. Pass arguments as a list: subprocess.run(['ls', '-l'])",
                "cwe_id": "CWE-78"
            },
            {
                "type": "Unsafe Deserialization",
                "severity": "HIGH",
                "pattern": r"pickle\.(?:loads|load)\(",
                "description": "Deserializing untrusted data with pickle. This can lead to arbitrary code execution.",
                "remediation": "Use safer serialization formats like JSON, or sign/encrypt pickle payloads.",
                "cwe_id": "CWE-502"
            },
            {
                "type": "Dynamic Code Execution",
                "severity": "HIGH",
                "pattern": r"\b(eval|exec)\(",
                "description": "Use of eval() or exec() allows execution of arbitrary string inputs.",
                "remediation": "Avoid dynamic code execution. Parse inputs structurally (e.g. using ast.literal_eval).",
                "cwe_id": "CWE-95"
            },
            {
                "type": "Insecure Flask/Django App Config",
                "severity": "MEDIUM",
                "pattern": r"DEBUG\s*=\s*True",
                "description": "Debug mode enabled in framework configuration. This exposes detailed stack traces and debugging consoles in production.",
                "remediation": "Set DEBUG = False in production environments.",
                "cwe_id": "CWE-489"
            }
        ]
        
        # JS/TS specific patterns
        self.js_patterns = [
            {
                "type": "DOM XSS Risk (innerHTML)",
                "severity": "HIGH",
                "pattern": r"\.innerHTML\s*=\s*.*?",
                "description": "Direct assignment to innerHTML without sanitization allows execution of arbitrary scripts.",
                "remediation": "UsetextContent or element.textContent, or sanitize using DOMPurify before setting innerHTML.",
                "cwe_id": "CWE-79"
            },
            {
                "type": "DOM XSS Risk (document.write)",
                "severity": "HIGH",
                "pattern": r"document\.write\(",
                "description": "Use of document.write() bypasses modern DOM protections and allows injection.",
                "remediation": "Use document.createElement() and safe DOM manipulation methods.",
                "cwe_id": "CWE-79"
            },
            {
                "type": "Dynamic Code Execution (eval)",
                "severity": "CRITICAL",
                "pattern": r"\beval\(",
                "description": "Use of eval() executes strings as code. Highly vulnerable to input injection.",
                "remediation": "Use JSON.parse() or structure logic without dynamic string execution.",
                "cwe_id": "CWE-95"
            },
            {
                "type": "Insecure Cookie Configuration",
                "severity": "MEDIUM",
                "pattern": r"document\.cookie\s*=\s*['\"].*?(?!Secure|HttpOnly).*?['\"]",
                "description": "Cookies set without Secure or HttpOnly attributes, making them vulnerable to session hijacking.",
                "remediation": "Ensure cookies are set with Secure; HttpOnly; SameSite=Strict/Lax attributes.",
                "cwe_id": "CWE-614"
            }
        ]

    def scan_content(self, filename: str, content: str) -> List[Dict[str, Any]]:
        """Scan file content and return vulnerabilities"""
        findings = []
        lines = content.splitlines()
        
        # Detect language
        ext = filename.split(".")[-1].lower() if "." in filename else ""
        is_py = ext in ("py", "python")
        is_js = ext in ("js", "jsx", "ts", "tsx", "html")
        
        # Run generic secret scans
        for secret_name, pattern in self.secret_patterns.items():
            regex = re.compile(pattern, re.IGNORECASE)
            for idx, line in enumerate(lines):
                # Ignore comments
                if line.strip().startswith("#") or line.strip().startswith("//"):
                    continue
                match = regex.search(line)
                if match:
                    findings.append({
                        "type": "Hardcoded Secret",
                        "severity": "CRITICAL",
                        "title": f"Hardcoded {secret_name} found",
                        "description": f"Potential leak of {secret_name} in variable definition.",
                        "url": filename,
                        "method": "STATIC",
                        "parameter": f"Line {idx+1}",
                        "payload": "Redacted Secret Value",
                        "evidence": line.strip(),
                        "remediation": "Move secrets to environment variables or use a secret manager.",
                        "cwe_id": "CWE-798",
                        "cvss_score": 8.9,
                        "ml_confidence": 0.95,
                        "location": f"{filename}:{idx+1}"
                    })
        
        # Language specific rules
        rules = []
        if is_py:
            rules = self.py_patterns
        elif is_js:
            rules = self.js_patterns
            
        for rule in rules:
            regex = re.compile(rule["pattern"])
            for idx, line in enumerate(lines):
                # Ignore comments
                if is_py and line.strip().startswith("#"):
                    continue
                if is_js and line.strip().startswith("//"):
                    continue
                if regex.search(line):
                    findings.append({
                        "type": rule["type"],
                        "severity": rule["severity"],
                        "title": rule["type"],
                        "description": rule["description"],
                        "url": filename,
                        "method": "STATIC",
                        "parameter": f"Line {idx+1}",
                        "payload": "N/A",
                        "evidence": line.strip(),
                        "remediation": rule["remediation"],
                        "cwe_id": rule["cwe_id"],
                        "cvss_score": 7.5 if rule["severity"] == "HIGH" else (9.0 if rule["severity"] == "CRITICAL" else 5.0),
                        "ml_confidence": 0.85,
                        "location": f"{filename}:{idx+1}"
                    })
                    
        return findings
