import React, { useState, useRef } from 'react';
import { Section } from '../components/Section';
import { Badge } from '../components/Badge';
import { COLORS } from '../constants/colors';

const API = "https://security-analyzer-api.onrender.com";

const SEV_COLOR = { CRITICAL: "#ff1744", HIGH: "#ff3b5c", MEDIUM: "#ffaa00", LOW: "#00e676", INFO: "#7c83fd" };

export const DemoTab = () => {
  const [url, setUrl] = useState("https://testphp.vulnweb.com");
  const [mode, setMode] = useState("passive");
  const [intensity, setIntensity] = useState(2);
  const [modules, setModules] = useState(["xss", "sqli", "csrf", "headers"]);
  const [phase, setPhase] = useState("idle"); // idle | scanning | done | error
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState([]);
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [elapsed, setElapsed] = useState(0);
  const [jobId, setJobId] = useState(null);
  const pollRef = useRef(null);
  const timerRef = useRef(null);

  const toggleModule = (m) => setModules(prev =>
    prev.includes(m) ? prev.filter(x => x !== m) : [...prev, m]
  );

  const startScan = async () => {
    setPhase("scanning");
    setProgress(5);
    setFindings([]);
    setResult(null);
    setErrorMsg("");
    setElapsed(0);

    const t0 = Date.now();
    timerRef.current = setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 1000);

    // Map module names to backend expected names
    const scanTypes = modules.map(m => m === "sqli" ? "sqli" : m);

    try {
      const res = await fetch(`${API}/scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim(), scan_types: scanTypes }),
      });

      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data = await res.json();
      setJobId(data.job_id);

      let ticks = 0;
      pollRef.current = setInterval(async () => {
        ticks++;
        setProgress(Math.min(90, 5 + ticks * 4));
        try {
          const pr = await fetch(`${API}/scan/status/${data.job_id}`);
          const pd = await pr.json();

          if (pd.status === "completed") {
            clearInterval(pollRef.current);
            clearInterval(timerRef.current);
            setProgress(100);
            setResult(pd.result);
            setFindings(pd.result?.findings || []);
            setPhase("done");
          } else if (pd.status === "failed") {
            clearInterval(pollRef.current);
            clearInterval(timerRef.current);
            setErrorMsg(pd.error || "Scan failed on server.");
            setPhase("error");
          }
        } catch (_) {}
      }, 3000);

    } catch (e) {
      clearInterval(timerRef.current);
      setErrorMsg(`Cannot reach backend: ${e.message}`);
      setPhase("error");
    }
  };

  const reset = () => {
    clearInterval(pollRef.current);
    clearInterval(timerRef.current);
    setPhase("idle");
    setProgress(0);
    setFindings([]);
    setResult(null);
    setJobId(null);
  };

  const downloadPDF = () => {
    if (!jobId) return;
    window.open(`${API}/report/pdf/${jobId}`, "_blank");
  };

  const sevCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const score = result?.security_score ?? null;

  return (
    <div>
      <Section title="Live Security Scanner">
        <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 24 }}>

          {/* URL Input */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ color: COLORS.textDim, fontSize: 12, display: "block", marginBottom: 6 }}>TARGET URL</label>
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              disabled={phase === "scanning"}
              placeholder="https://example.com"
              style={{ width: "100%", background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "10px 14px", color: COLORS.text, fontSize: 14, fontFamily: "monospace", boxSizing: "border-box" }}
            />
          </div>

          {/* Mode + Intensity + Modules */}
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
                {["xss", "sqli", "csrf", "headers"].map(m => (
                  <button key={m} onClick={() => toggleModule(m)} disabled={phase === "scanning"}
                    style={{ background: modules.includes(m) ? COLORS.accent + "22" : "transparent", border: `1px solid ${modules.includes(m) ? COLORS.accent : COLORS.border}`, color: modules.includes(m) ? COLORS.accent : COLORS.muted, borderRadius: 4, padding: "6px 12px", fontSize: 11, fontFamily: "monospace", cursor: "pointer", fontWeight: 700 }}>
                    {m.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
            <button
              onClick={phase === "idle" || phase === "error" ? startScan : reset}
              disabled={phase === "scanning" && false}
              style={{ background: phase === "scanning" ? COLORS.muted : COLORS.accent, color: "#000", border: "none", borderRadius: 8, padding: "12px 32px", fontSize: 14, fontWeight: 800, cursor: "pointer", letterSpacing: 1 }}>
              {phase === "idle" ? "▶  RUN SCAN" : phase === "scanning" ? "■  CANCEL" : "↺  NEW SCAN"}
            </button>

            {phase === "done" && jobId && (
              <button onClick={downloadPDF}
                style={{ background: "transparent", border: `1px solid ${COLORS.accent}`, color: COLORS.accent, borderRadius: 8, padding: "12px 24px", fontSize: 13, fontWeight: 700, cursor: "pointer" }}>
                📄 Download PDF Report
              </button>
            )}

            {phase === "scanning" && (
              <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ flex: 1, background: COLORS.surface, borderRadius: 4, height: 8, overflow: "hidden" }}>
                  <div style={{ width: `${progress}%`, height: "100%", background: `linear-gradient(90deg, ${COLORS.accent}, ${COLORS.info})`, transition: "width 0.4s" }} />
                </div>
                <span style={{ color: COLORS.accent, fontSize: 13, fontFamily: "monospace", minWidth: 60 }}>{elapsed}s</span>
              </div>
            )}
          </div>

          {/* Error */}
          {phase === "error" && (
            <div style={{ marginTop: 16, background: "#ff174420", border: "1px solid #ff174440", borderRadius: 8, padding: "12px 16px", color: "#ff1744", fontSize: 13 }}>
              ⚠️ {errorMsg}
            </div>
          )}
        </div>
      </Section>

      {/* Results */}
      {(findings.length > 0 || phase === "done") && result && (
        <Section title="Scan Results" accent={COLORS.danger}>

          {/* Score + Counts */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 10, marginBottom: 20 }}>
            <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 14, textAlign: "center", gridColumn: "span 2" }}>
              <div style={{ fontSize: 32, fontWeight: 900, color: score >= 80 ? COLORS.success : score >= 50 ? COLORS.warn : COLORS.danger }}>
                {score}
              </div>
              <div style={{ color: COLORS.textDim, fontSize: 11, marginTop: 4 }}>SECURITY SCORE / 100</div>
            </div>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
              <div key={s} style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 14, textAlign: "center" }}>
                <div style={{ fontSize: 24, fontWeight: 900, color: SEV_COLOR[s] }}>{sevCounts[s] || 0}</div>
                <div style={{ color: COLORS.textDim, fontSize: 10, marginTop: 4 }}>{s}</div>
              </div>
            ))}
          </div>

          {/* Pages scanned info */}
          <div style={{ color: COLORS.textDim, fontSize: 12, marginBottom: 16 }}>
            ✅ Scanned <strong style={{ color: COLORS.text }}>{result.pages_scanned}</strong> pages on <strong style={{ color: COLORS.accent }}>{result.target_url}</strong> in <strong style={{ color: COLORS.text }}>{result.scan_time_seconds}s</strong> — {result.total_findings} total findings
          </div>

          {/* Findings list */}
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {findings.length === 0 ? (
              <div style={{ textAlign: "center", padding: 40, color: COLORS.textDim }}>
                ✅ No vulnerabilities found
              </div>
            ) : findings.map((f, i) => (
              <div key={i} style={{ background: COLORS.card, border: `1px solid ${SEV_COLOR[f.severity] || "#7c83fd"}33`, borderLeft: `4px solid ${SEV_COLOR[f.severity] || "#7c83fd"}`, borderRadius: 8, padding: 16 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <Badge label={f.severity} color={SEV_COLOR[f.severity] || "#7c83fd"} />
                  <span style={{ color: COLORS.text, fontWeight: 700, fontSize: 14 }}>
                    {(f.type || "").replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
                  </span>
                  <code style={{ color: COLORS.textDim, fontSize: 11, marginLeft: "auto" }}>{f.location}</code>
                </div>
                <p style={{ color: COLORS.textDim, fontSize: 13, margin: "0 0 8px", lineHeight: 1.5 }}>{f.evidence}</p>
                {f.payload && f.payload !== "N/A" && (
                  <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                    <span style={{ color: COLORS.muted, fontSize: 11 }}>param: <code style={{ color: COLORS.warn }}>{f.parameter}</code></span>
                    <span style={{ color: COLORS.muted, fontSize: 11 }}>payload: <code style={{ color: COLORS.danger }}>{f.payload}</code></span>
                    <span style={{ color: COLORS.muted, fontSize: 11 }}>url: <code style={{ color: COLORS.textDim, fontSize: 10 }}>{f.url?.slice(0, 60)}</code></span>
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