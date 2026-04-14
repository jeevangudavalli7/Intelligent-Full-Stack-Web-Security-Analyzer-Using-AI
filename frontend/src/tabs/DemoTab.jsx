import React, { useState, useEffect, useRef } from 'react';
import { Section } from '../components/Section';
import { Badge } from '../components/Badge';
import { COLORS } from '../constants/colors';
import { createScan, getScanResults } from '../api/scans';

const SEV = { CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", INFO: "INFO" };
const SEV_COLOR = { CRITICAL: "#ff1744", HIGH: "#ff3b5c", MEDIUM: "#ffaa00", LOW: "#00e676", INFO: "#7c83fd" };

const MOCK_FINDINGS = [
  { id: 1, type: "SQL Injection", sev: SEV.CRITICAL, url: "/api/users", param: "id", payload: "' OR 1=1 --", confidence: 0.97, desc: "Time-based blind SQL injection detected in the 'id' parameter. Attacker can exfiltrate the entire database." },
  { id: 2, type: "Reflected XSS", sev: SEV.HIGH, url: "/search", param: "q", payload: "<script>alert(1)</script>", confidence: 0.91, desc: "User input echoed back unescaped in search results page, allowing script injection." },
  { id: 3, type: "CSRF", sev: SEV.HIGH, url: "/account/delete", param: "N/A", payload: "N/A", confidence: 0.88, desc: "Account deletion endpoint lacks CSRF token. Attackers can delete accounts via forged requests." },
  { id: 4, type: "Missing CSP", sev: SEV.MEDIUM, url: "/", param: "N/A", payload: "N/A", confidence: 0.99, desc: "Content-Security-Policy header absent, enabling XSS escalation." },
  { id: 5, type: "DOM XSS", sev: SEV.MEDIUM, url: "/dashboard", param: "hash", payload: "#<img onerror=...>", confidence: 0.74, desc: "Dangerous innerHTML sink detected in dashboard JS, consuming URL fragment." },
  { id: 6, type: "Insecure Cookie", sev: SEV.LOW, url: "All", param: "session", payload: "N/A", confidence: 0.95, desc: "Session cookie missing HttpOnly and SameSite=Strict flags." },
];

export const DemoTab = () => {
  const [url, setUrl] = useState("https://example-vulnerable-app.com");
  const [mode, setMode] = useState("passive");
  const [intensity, setIntensity] = useState(2);
  const [modules, setModules] = useState(["xss", "sqli", "csrf"]);
  const [phase, setPhase] = useState("idle"); // idle | scanning | done
  const [progress, setProgress] = useState(0);
  const [currentModule, setCurrentModule] = useState("");
  const [findings, setFindings] = useState([]);
  const [scanId, setScanId] = useState(null);
  const intervalRef = useRef(null);

  const MODULES_ORDER = ["xss", "sqli", "csrf", "headers", "cookies"];

  const startScan = async () => {
    setPhase("scanning");
    setProgress(0);
    setFindings([]);
    // In a real app, you'd call the API to start the scan
    // const response = await createScan(url, mode, intensity, modules);
    // setScanId(response.scan_id);
    // For demo, we simulate progress
    let pct = 0;
    let modIdx = 0;
    setCurrentModule(MODULES_ORDER[0]);

    intervalRef.current = setInterval(() => {
      pct += Math.random() * 8 + 2;
      if (pct >= 100) { pct = 100; }
      setProgress(Math.round(pct));
      modIdx = Math.floor((pct / 100) * MODULES_ORDER.length);
      setCurrentModule(MODULES_ORDER[Math.min(modIdx, MODULES_ORDER.length - 1)]);

      // Drip in findings
      const findingIdx = Math.floor((pct / 100) * MOCK_FINDINGS.length);
      setFindings(MOCK_FINDINGS.slice(0, findingIdx));

      if (pct >= 100) {
        clearInterval(intervalRef.current);
        setFindings(MOCK_FINDINGS);
        setPhase("done");
      }
    }, 300);
  };

  const reset = () => {
    clearInterval(intervalRef.current);
    setPhase("idle");
    setProgress(0);
    setFindings([]);
  };

  const toggleModule = (m) => setModules(prev =>
    prev.includes(m) ? prev.filter(x => x !== m) : [...prev, m]
  );

  const sevCounts = findings.reduce((acc, f) => { acc[f.sev] = (acc[f.sev] || 0) + 1; return acc; }, {});
  const riskScore = findings.length === 0 ? 0 : Math.min(10, (
    (sevCounts.CRITICAL || 0) * 3 + (sevCounts.HIGH || 0) * 1.5 +
    (sevCounts.MEDIUM || 0) * 0.5 + (sevCounts.LOW || 0) * 0.1
  )).toFixed(1);

  return (
    <div>
      <Section title="Interactive Demo — Configure Scan">
        <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 24 }}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ color: COLORS.textDim, fontSize: 12, display: "block", marginBottom: 6 }}>TARGET URL</label>
            <input value={url} onChange={e => setUrl(e.target.value)}
              disabled={phase === "scanning"}
              style={{ width: "100%", background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "10px 14px", color: COLORS.text, fontSize: 14, fontFamily: "monospace", boxSizing: "border-box" }} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 2fr", gap: 16, marginBottom: 20 }}>
            <div>
              <label style={{ color: COLORS.textDim, fontSize: 12, display: "block", marginBottom: 6 }}>SCAN MODE</label>
              <select value={mode} onChange={e => setMode(e.target.value)} disabled={phase === "scanning"}
                style={{ width: "100%", background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "10px 14px", color: COLORS.text, fontSize: 13 }}>
                <option value="passive">Passive</option>
                <option value="active">Active</option>
              </select>
            </div>
            <div>
              <label style={{ color: COLORS.textDim, fontSize: 12, display: "block", marginBottom: 6 }}>INTENSITY</label>
              <select value={intensity} onChange={e => setIntensity(Number(e.target.value))} disabled={phase === "scanning"}
                style={{ width: "100%", background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "10px 14px", color: COLORS.text, fontSize: 13 }}>
                <option value={1}>1 — Low</option>
                <option value={2}>2 — Medium</option>
                <option value={3}>3 — High</option>
              </select>
            </div>
            <div>
              <label style={{ color: COLORS.textDim, fontSize: 12, display: "block", marginBottom: 6 }}>MODULES</label>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {["xss", "sqli", "csrf", "headers", "ssrf"].map(m => (
                  <button key={m} onClick={() => toggleModule(m)} disabled={phase === "scanning"}
                    style={{ background: modules.includes(m) ? COLORS.accent + "22" : "transparent", border: `1px solid ${modules.includes(m) ? COLORS.accent : COLORS.border}`, color: modules.includes(m) ? COLORS.accent : COLORS.muted, borderRadius: 4, padding: "6px 12px", fontSize: 11, fontFamily: "monospace", cursor: "pointer", fontWeight: 700 }}>
                    {m.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 12 }}>
            <button onClick={phase === "idle" ? startScan : reset}
              style={{ background: phase === "idle" ? COLORS.accent : COLORS.muted, color: "#000", border: "none", borderRadius: 8, padding: "12px 32px", fontSize: 14, fontWeight: 800, cursor: "pointer", letterSpacing: 1 }}>
              {phase === "idle" ? "▶  RUN SCAN" : phase === "scanning" ? "■  CANCEL" : "↺  NEW SCAN"}
            </button>
            {phase === "scanning" && (
              <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ flex: 1, background: COLORS.surface, borderRadius: 4, height: 8, overflow: "hidden" }}>
                  <div style={{ width: `${progress}%`, height: "100%", background: `linear-gradient(90deg, ${COLORS.accent}, ${COLORS.info})`, transition: "width 0.3s" }} />
                </div>
                <span style={{ color: COLORS.accent, fontSize: 13, fontFamily: "monospace", minWidth: 50 }}>{progress}%</span>
                <Badge label={currentModule.toUpperCase()} color={COLORS.warn} />
              </div>
            )}
          </div>
        </div>
      </Section>

      {findings.length > 0 && (
        <Section title="Scan Results" accent={COLORS.danger}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 10, marginBottom: 20 }}>
            <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 14, textAlign: "center", gridColumn: "span 2" }}>
              <div style={{ fontSize: 32, fontWeight: 900, color: Number(riskScore) >= 7 ? COLORS.danger : Number(riskScore) >= 4 ? COLORS.warn : COLORS.success }}>{riskScore}</div>
              <div style={{ color: COLORS.textDim, fontSize: 11, marginTop: 4 }}>RISK SCORE / 10</div>
            </div>
            {[SEV.CRITICAL, SEV.HIGH, SEV.MEDIUM, SEV.LOW].map(s => (
              <div key={s} style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 14, textAlign: "center" }}>
                <div style={{ fontSize: 24, fontWeight: 900, color: SEV_COLOR[s] }}>{sevCounts[s] || 0}</div>
                <div style={{ color: COLORS.textDim, fontSize: 10, marginTop: 4 }}>{s}</div>
              </div>
            ))}
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {findings.map(f => (
              <div key={f.id} style={{ background: COLORS.card, border: `1px solid ${SEV_COLOR[f.sev]}33`, borderLeft: `4px solid ${SEV_COLOR[f.sev]}`, borderRadius: 8, padding: 16 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <Badge label={f.sev} color={SEV_COLOR[f.sev]} />
                  <span style={{ color: COLORS.text, fontWeight: 700, fontSize: 14 }}>{f.type}</span>
                  <code style={{ color: COLORS.textDim, fontSize: 11, marginLeft: "auto" }}>{f.url}</code>
                  <span style={{ color: COLORS.muted, fontSize: 11, fontFamily: "monospace" }}>conf: {(f.confidence * 100).toFixed(0)}%</span>
                </div>
                <p style={{ color: COLORS.textDim, fontSize: 13, margin: "0 0 8px", lineHeight: 1.5 }}>{f.desc}</p>
                {f.payload !== "N/A" && (
                  <div style={{ display: "flex", gap: 16 }}>
                    <span style={{ color: COLORS.muted, fontSize: 11 }}>param: <code style={{ color: COLORS.warn }}>{f.param}</code></span>
                    <span style={{ color: COLORS.muted, fontSize: 11 }}>payload: <code style={{ color: COLORS.danger }}>{f.payload}</code></span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
};