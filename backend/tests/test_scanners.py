import pytest
from scanner.sast_scanner import SASTScanner
from scanner.config_auditor import ConfigAuditor

def test_sast_scanner_secrets():
    scanner = SASTScanner()
    content = "aws_key = 'AKIA1234567890ABCDEF'"
    findings = scanner.scan_content("test.py", content)
    assert len(findings) > 0
    assert findings[0]["type"] == "Hardcoded Secret"

def test_sast_scanner_sqli():
    scanner = SASTScanner()
    content = "db.execute(f'SELECT * FROM users WHERE id = {user_id}')"
    findings = scanner.scan_content("db.py", content)
    assert len(findings) > 0
    assert "SQL Injection" in findings[0]["type"]

def test_config_auditor_dockerfile():
    auditor = ConfigAuditor()
    content = "FROM node:latest\nHEALTHCHECK --interval=5m CMD curl -f http://localhost/ || exit 1"
    findings = auditor.audit_dockerfile("Dockerfile", content)
    # Should flag missing USER configuration and latest base image tag
    types = [f["type"] for f in findings]
    assert "Missing Dockerfile USER Configuration" in types
    assert "Insecure Dockerfile Base Image" in types
