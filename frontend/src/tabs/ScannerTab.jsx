import React from 'react';
import { Section } from '../components/Section';
import { CodeBlock } from '../components/CodeBlock';
import { COLORS } from '../constants/colors';

export const ScannerTab = () => {
  const sqliCode = `# scanner/sqli_scanner.py
import re, requests, logging
from dataclasses import dataclass
from typing import List, Optional
from ml.classifier import VulnClassifier
from utils.http_client import SafeHTTPClient

@dataclass
class Finding:
    vuln_type: str
    url: str
    parameter: str
    payload: str
    evidence: str
    confidence: float      # ML model score 0-1
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW

SQLI_PAYLOADS = {
    "passive": [
        "' OR '1'='1",
        "'; --",
        "1 AND 1=1",
        '" OR "1"="1',
    ],
    "active": [
        "' OR SLEEP(5) --",           # Time-based blind
        "' UNION SELECT NULL,NULL --",  # Union-based
        "'; EXEC xp_cmdshell('dir'); --",  # MSSQL
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    ]
}

ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"ORA-\\d{5}",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark",
    r"SQLite3::Exception",
    r"pg_query\\(\\): Query failed",
]

class SQLiScanner:
    def __init__(self, mode: str = "passive", intensity: int = 1):
        self.mode = mode
        self.intensity = intensity          # 1=low, 2=medium, 3=high
        self.http = SafeHTTPClient(timeout=10)
        self.classifier = VulnClassifier.load("models/sqli_xgb_v2.pkl")
        self.logger = logging.getLogger(__name__)

    def scan(self, url: str, params: dict) -> List[Finding]:
        findings = []
        payloads = SQLI_PAYLOADS[self.mode]
        if self.intensity >= 2:
            payloads += self._load_extended_payloads()

        for param_name in params:
            for payload in payloads:
                finding = self._test_payload(url, params, param_name, payload)
                if finding:
                    findings.append(finding)
                    if self.mode == "passive":
                        break   # stop at first hit in passive mode
        return findings

    def _test_payload(self, url, params, param, payload) -> Optional[Finding]:
        mutated = {**params, param: payload}
        try:
            baseline = self.http.get(url, params=params)
            response = self.http.get(url, params=mutated)
        except Exception as e:
            self.logger.warning(f"Request failed: {e}")
            return None

        # Rule-based detection
        rule_hit = self._check_error_patterns(response.text)

        # Time-based detection
        time_hit = response.elapsed.total_seconds() > 4.5

        # ML feature extraction + scoring
        features = self._extract_features(baseline, response, payload)
        ml_score = self.classifier.predict_proba(features)[1]   # P(vulnerable)

        confidence = self._fuse_signals(rule_hit, time_hit, ml_score)

        if confidence >= 0.65:
            return Finding(
                vuln_type="SQL Injection",
                url=url,
                parameter=param,
                payload=payload,
                evidence=response.text[:300],
                confidence=confidence,
                severity=self._severity(confidence)
            )
        return None

    def _check_error_patterns(self, body: str) -> bool:
        return any(re.search(p, body, re.I) for p in ERROR_PATTERNS)

    def _extract_features(self, baseline, response, payload) -> list:
        return [
            len(response.text) - len(baseline.text),     # body size delta
            response.status_code,
            response.elapsed.total_seconds(),
            int(self._check_error_patterns(response.text)),
            len(payload),
            payload.count("'"),
            payload.count("--"),
            int("UNION" in payload.upper()),
            int("SLEEP" in payload.upper()),
        ]

    def _fuse_signals(self, rule: bool, time: bool, ml: float) -> float:
        base = ml
        if rule: base = min(1.0, base + 0.25)
        if time: base = min(1.0, base + 0.20)
        return round(base, 3)

    def _severity(self, confidence: float) -> str:
        if confidence >= 0.90: return "CRITICAL"
        if confidence >= 0.75: return "HIGH"
        if confidence >= 0.60: return "MEDIUM"
        return "LOW"

    def _load_extended_payloads(self) -> list:
        # Load from curated payload database
        from db.payloads import PayloadStore
        return PayloadStore.get("sqli", tier=self.intensity)`;

  const xssCode = `# scanner/xss_scanner.py
from bs4 import BeautifulSoup
import re, html

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    '<svg onload=alert(1)>',
    '"><script>alert(String.fromCharCode(88,83,83))</script>',
]

DOM_SINKS = [
    r"document\\.write\\(", r"innerHTML\\s*=",
    r"eval\\(", r"setTimeout\\(", r"location\\.href\\s*=",
]

class XSSScanner:
    def scan_reflected(self, url, params) -> List[Finding]:
        """Test if payloads echo back unescaped in response HTML."""
        findings = []
        for param, _ in params.items():
            for payload in XSS_PAYLOADS:
                resp = self.http.get(url, params={**params, param: payload})
                soup = BeautifulSoup(resp.text, "html.parser")
                # Check if payload appears unescaped
                raw_text = resp.text
                escaped = html.escape(payload)
                if payload in raw_text and escaped not in raw_text:
                    findings.append(Finding(
                        vuln_type="Reflected XSS",
                        parameter=param, payload=payload,
                        evidence=self._extract_context(raw_text, payload),
                        confidence=0.92, severity="HIGH"
                    ))
        return findings

    def scan_dom(self, html_content: str) -> List[Finding]:
        """Static analysis of JS for dangerous DOM sinks."""
        findings = []
        scripts = BeautifulSoup(html_content, "html.parser").find_all("script")
        for script in scripts:
            for sink_pattern in DOM_SINKS:
                if re.search(sink_pattern, script.string or ""):
                    findings.append(Finding(
                        vuln_type="DOM-based XSS (potential)",
                        evidence=script.string[:200],
                        confidence=0.70, severity="MEDIUM"
                    ))
        return findings`;

  return (
    <div>
      <Section title="Scanner Module Architecture">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 24 }}>
          {[
            { name: "XSS Scanner", types: ["Reflected", "Stored", "DOM-based"], tech: "BeautifulSoup + Selenium + ML", color: COLORS.danger },
            { name: "SQL Injection", types: ["Error-based", "Blind/Time", "Union-based"], tech: "Regex + XGBoost Classifier", color: COLORS.warn },
            { name: "CSRF Scanner", types: ["Token absence", "Weak tokens", "SameSite"], tech: "Token entropy analysis", color: COLORS.info },
            { name: "SSRF Scanner", types: ["Internal endpoints", "Cloud metadata"], tech: "DNS rebind detection", color: COLORS.success },
            { name: "Header Analyzer", types: ["CSP missing", "HSTS", "X-Frame"], tech: "Policy parser", color: COLORS.accent },
            { name: "Auth Scanner", types: ["Broken auth", "Session fixation"], tech: "Behavioral analysis", color: "#f06292" },
          ].map(s => (
            <div key={s.name} style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 16 }}>
              <div style={{ color: s.color, fontWeight: 700, fontSize: 13, marginBottom: 8 }}>{s.name}</div>
              <div style={{ marginBottom: 10 }}>
                {s.types.map(t => <div key={t} style={{ color: COLORS.textDim, fontSize: 12, padding: "2px 0" }}>• {t}</div>)}
              </div>
              <div style={{ color: COLORS.muted, fontSize: 11, fontFamily: "monospace", borderTop: `1px solid ${COLORS.border}`, paddingTop: 8 }}>{s.tech}</div>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Scan Modes & Intensity Matrix" accent={COLORS.warn}>
        <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 10, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ background: COLORS.surface }}>
                {["Mode / Intensity", "Passive L1", "Passive L2", "Active L1", "Active L2", "Active L3"].map(h => (
                  <th key={h} style={{ padding: "12px 16px", color: COLORS.accent, fontWeight: 700, textAlign: "left", borderBottom: `1px solid ${COLORS.border}` }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                ["Payloads / Param", "4", "12", "20", "50", "200+"],
                ["Concurrency", "1", "2", "4", "8", "16"],
                ["DOM Analysis", "✗", "✓", "✗", "✓", "✓"],
                ["Time-based Checks", "✗", "✗", "✓", "✓", "✓"],
                ["Auth Bypass Tests", "✗", "✗", "✗", "✓", "✓"],
                ["Crawl Depth", "0", "1", "1", "3", "5"],
                ["Avg Duration", "~5s", "~20s", "~30s", "~2min", "~10min"],
              ].map((row, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${COLORS.border}33` }}>
                  {row.map((cell, j) => (
                    <td key={j} style={{ padding: "10px 16px", color: j === 0 ? COLORS.text : COLORS.textDim, fontFamily: j > 0 ? "monospace" : "inherit" }}>{cell}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="SQLi Scanner — Full Implementation" accent={COLORS.success}>
        <CodeBlock code={sqliCode} lang="python" />
      </Section>

      <Section title="XSS Scanner — Core Logic" accent={COLORS.danger}>
        <CodeBlock code={xssCode} lang="python" />
      </Section>
    </div>
  );
};