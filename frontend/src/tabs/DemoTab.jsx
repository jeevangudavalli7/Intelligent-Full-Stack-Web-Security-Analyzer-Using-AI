// frontend/src/tabs/DemoTab.jsx
import React, { useState, useRef, useEffect } from 'react';

const API = '';

const SEV_THEME = {
  CRITICAL: { color: '#ef4444', bg: '#fee2e2', border: '#fca5a5' },
  HIGH:     { color: '#f97316', bg: '#ffedd5', border: '#fed7aa' },
  MEDIUM:   { color: '#eab308', bg: '#fef9c3', border: '#fef08a' },
  LOW:      { color: '#3b82f6', bg: '#dbeafe', border: '#bfdbfe' },
  INFO:     { color: '#6b7280', bg: '#f3f4f6', border: '#e5e7eb' },
};

function SeverityBadge({ level }) {
  const normalized = (level || 'INFO').toUpperCase();
  const theme = SEV_THEME[normalized] || SEV_THEME.INFO;
  return (
    <span style={{
      background: theme.bg,
      color: theme.color,
      border: `1px solid ${theme.border}`,
      borderRadius: '6px',
      padding: '2px 8px',
      fontSize: '11px',
      fontFamily: 'var(--mono)',
      fontWeight: '600',
      textTransform: 'uppercase'
    }}>
      {normalized}
    </span>
  );
}

export const DemoTab = () => {
  const [target, setTarget] = useState('c:\\Users\\jeeva\\Desktop\\GithubLargefiles\\Intelligent-Full-Stack-Web-Security-Analyzer-Using-AI');
  const [modules, setModules] = useState(['sast', 'config', 'headers']);
  const [phase, setPhase] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState([]);
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [elapsed, setElapsed] = useState(0);
  const [jobId, setJobId] = useState(null);
  const [expanded, setExpanded] = useState(null);
  
  // Filtering & Search
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  
  const pollRef = useRef(null);
  const timerRef = useRef(null);

  const startScan = async () => {
    if (phase === 'scanning') return;
    setPhase('scanning');
    setProgress(10);
    setFindings([]);
    setResult(null);
    setErrorMsg('');
    setElapsed(0);
    setExpanded(null);
    
    const t0 = Date.now();
    timerRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - t0) / 1000));
    }, 1000);
    
    try {
      const res = await fetch(`${API}/scan/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target.trim(), scan_types: modules }),
      });
      
      if (!res.ok) throw new Error(`Backend returned HTTP ${res.status}`);
      const { job_id } = await res.json();
      setJobId(job_id);
      
      let ticks = 0;
      pollRef.current = setInterval(async () => {
        ticks++;
        setProgress(p => Math.min(95, p + 8));
        try {
          const pr = await fetch(`${API}/scan/status/${job_id}`);
          const pd = await pr.json();
          
          if (pd.status === 'completed' || pd.status === 'COMPLETE') {
            clearInterval(pollRef.current);
            clearInterval(timerRef.current);
            setProgress(100);
            
            const scanResult = pd.result || pd;
            setResult(scanResult);
            setFindings(scanResult.findings || []);
            setPhase('done');
          } else if (pd.status === 'failed') {
            clearInterval(pollRef.current);
            clearInterval(timerRef.current);
            setErrorMsg(pd.error || 'Scan execution failed on server.');
            setPhase('error');
          }
        } catch (_) {
          // ignore network hiccups
        }
      }, 1500);
      
    } catch (e) {
      clearInterval(timerRef.current);
      setErrorMsg(`Connection error to scanner service:\n${e.message}\n\nPlease check if backend service is running locally.`);
      setPhase('error');
    }
  };

  const reset = () => {
    clearInterval(pollRef.current);
    clearInterval(timerRef.current);
    setPhase('idle');
    setProgress(0);
    setFindings([]);
    setResult(null);
    setJobId(null);
  };

  useEffect(() => {
    return () => {
      clearInterval(pollRef.current);
      clearInterval(timerRef.current);
    };
  }, []);

  const counts = findings.reduce((acc, f) => {
    const s = f.severity.toUpperCase();
    acc[s] = (acc[s] || 0) + 1;
    acc.TOTAL = acc.TOTAL + 1;
    return acc;
  }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, TOTAL: 0 });

  const filteredFindings = findings.filter(f => {
    const matchesSev = severityFilter === 'ALL' || f.severity.toUpperCase() === severityFilter;
    const matchesSearch = f.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          f.location.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          f.description.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSev && matchesSearch;
  });

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'grid', gridTemplateColumns: '320px 1fr', gap: '28px' }}>
      
      {/* ── LEFT PANEL: Scan Configuration ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '12px', padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <span style={{ fontSize: '20px' }}>🛡️</span>
            <h3 style={{ margin: 0, fontSize: '15px', fontWeight: '600', letterSpacing: '0.5px' }}>Security Audit Console</h3>
          </div>
          
          {/* Target Input */}
          <div style={{ marginBottom: '18px' }}>
            <label style={{ display: 'block', fontSize: '11px', fontWeight: '600', color: 'var(--text-dim)', marginBottom: '8px', fontFamily: 'var(--mono)', letterSpacing: '1px' }}>AUDIT TARGET</label>
            <input 
              value={target} 
              onChange={e => setTarget(e.target.value)} 
              disabled={phase === 'scanning'}
              placeholder="e.g. C:\workspace\project or https://domain.com"
              style={{
                width: '100%',
                padding: '10px 12px',
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                color: 'var(--text)',
                fontSize: '13px',
                fontFamily: 'var(--mono)',
                outline: 'none',
                transition: 'border-color 0.2s'
              }}
            />
            <span style={{ display: 'block', fontSize: '10px', color: 'var(--text-muted)', marginTop: '5px' }}>
              Provide a local directory path to run SAST and Configuration checks, or a web URL for HTTP compliance audit.
            </span>
          </div>

          {/* Module Select */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{ display: 'block', fontSize: '11px', fontWeight: '600', color: 'var(--text-dim)', marginBottom: '10px', fontFamily: 'var(--mono)', letterSpacing: '1px' }}>SECURITY SCOPE</label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {[
                { id: 'sast', label: 'SAST Code Analyzer', desc: 'Scan code for SQLi/XSS/Secrets' },
                { id: 'config', label: 'IaC Config Auditor', desc: 'Audit Docker/K8s/Dependencies' },
                { id: 'headers', label: 'Passive Web Auditor', desc: 'Inspect external HTTP headers' },
              ].map(m => {
                const active = modules.includes(m.id);
                return (
                  <label key={m.id} style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    padding: '10px',
                    borderRadius: '8px',
                    border: '1px solid var(--border)',
                    background: active ? 'var(--accent-glow)' : 'transparent',
                    cursor: phase === 'scanning' ? 'not-allowed' : 'pointer',
                    transition: 'all 0.15s'
                  }}>
                    <input 
                      type="checkbox" 
                      checked={active}
                      disabled={phase === 'scanning'}
                      onChange={() => {
                        setModules(prev => prev.includes(m.id) ? prev.filter(x => x !== m.id) : [...prev, m.id]);
                      }}
                      style={{ marginTop: '3px' }}
                    />
                    <div>
                      <div style={{ fontSize: '12px', fontWeight: '600', color: active ? 'var(--accent)' : 'var(--text)' }}>{m.label}</div>
                      <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>{m.desc}</div>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          {/* Actions */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <button 
              onClick={phase === 'scanning' ? reset : startScan}
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '8px',
                border: 'none',
                background: phase === 'scanning' ? 'var(--text-muted)' : 'var(--accent)',
                color: '#000',
                fontWeight: '600',
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.2s',
                fontFamily: 'var(--sans)',
                boxShadow: phase === 'scanning' ? 'none' : '0 4px 12px var(--accent-glow)'
              }}
            >
              {phase === 'idle' || phase === 'error' ? '⚡ Run Security Scan' : phase === 'scanning' ? '🛑 Cancel Scan' : '🔄 New Audit'}
            </button>
            
            {phase === 'done' && jobId && (
              <a 
                href={`${API}/report/pdf/${jobId}`} 
                target="_blank" 
                rel="noreferrer"
                style={{
                  width: '100%',
                  padding: '10px',
                  borderRadius: '8px',
                  border: '1px solid var(--accent)',
                  background: 'transparent',
                  color: 'var(--accent)',
                  fontWeight: '600',
                  fontSize: '13px',
                  textAlign: 'center',
                  cursor: 'pointer',
                  textDecoration: 'none',
                  display: 'block',
                  transition: 'all 0.2s'
                }}
              >
                📄 Export Security Report
              </a>
            )}
          </div>
        </div>

        {/* Scan Status Progress */}
        {phase === 'scanning' && (
          <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '12px', padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '11px', fontFamily: 'var(--mono)' }}>
              <span style={{ color: 'var(--text-dim)' }}>AUDITING TARGET...</span>
              <span style={{ color: 'var(--accent)', fontWeight: 'bold' }}>{elapsed}s</span>
            </div>
            <div style={{ height: '6px', background: 'var(--bg)', borderRadius: '3px', overflow: 'hidden', marginBottom: '10px' }}>
              <div style={{ width: `${progress}%`, height: '100%', background: 'var(--accent)', transition: 'width 0.3s ease' }} />
            </div>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Analyzing file AST and code structure...</span>
          </div>
        )}

        {phase === 'error' && (
          <div style={{ background: 'var(--danger-dim)', border: '1px solid var(--danger)', borderRadius: '12px', padding: '16px', color: 'var(--danger)', fontSize: '12px', whiteSpace: 'pre-line' }}>
            {errorMsg}
          </div>
        )}
      </div>

      {/* ── RIGHT PANEL: Scan Results Dashboard ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        
        {/* Statistics Bar */}
        {phase === 'done' && result && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px' }}>
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '10px', padding: '16px', textAlign: 'center' }}>
              <div style={{ fontSize: '28px', fontWeight: 'bold', color: result.security_score >= 80 ? 'var(--success)' : (result.security_score >= 50 ? 'var(--warn)' : 'var(--danger)'), fontFamily: 'var(--mono)' }}>
                {result.security_score}/100
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: '4px', letterSpacing: '0.5px' }}>Compliance Score</div>
            </div>
            
            {[
              { label: 'CRITICAL', color: '#ef4444', count: counts.CRITICAL },
              { label: 'HIGH', color: '#f97316', count: counts.HIGH },
              { label: 'MEDIUM', color: '#eab308', count: counts.MEDIUM },
              { label: 'LOW', color: '#3b82f6', count: counts.LOW }
            ].map(s => (
              <div key={s.label} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '10px', padding: '16px', textAlign: 'center' }}>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: s.color, fontFamily: 'var(--mono)' }}>
                  {s.count}
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: '4px', letterSpacing: '0.5px' }}>{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Findings Workspace */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '12px', padding: '24px', flex: 1, display: 'flex', flexDirection: 'column' }}>
          
          {phase === 'idle' && (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
              <span style={{ fontSize: '48px', marginBottom: '16px' }}>🔍</span>
              <h4 style={{ color: 'var(--text)', margin: '0 0 8px 0' }}>Ready for Audit</h4>
              <p style={{ margin: 0, fontSize: '13px', textAlign: 'center', maxWidth: '380px' }}>
                Select your scan scope, set target path or remote URL, and start checking to retrieve immediate vulnerabilities, locations, and remediation guidelines.
              </p>
            </div>
          )}

          {phase === 'done' && (
            <>
              {/* Toolbar */}
              <div style={{ display: 'flex', gap: '14px', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: '16px', marginBottom: '16px' }}>
                <input 
                  type="text"
                  placeholder="Search vulnerabilities, files..."
                  value={searchTerm}
                  onChange={e => setSearchTerm(e.target.value)}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--border)',
                    background: 'var(--bg)',
                    color: 'var(--text)',
                    fontSize: '13px',
                    outline: 'none'
                  }}
                />
                
                <div style={{ display: 'flex', gap: '6px' }}>
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(tab => (
                    <button
                      key={tab}
                      onClick={() => setSeverityFilter(tab)}
                      style={{
                        padding: '6px 12px',
                        borderRadius: '6px',
                        border: '1px solid',
                        borderColor: severityFilter === tab ? 'var(--accent)' : 'var(--border)',
                        background: severityFilter === tab ? 'var(--accent-glow)' : 'transparent',
                        color: severityFilter === tab ? 'var(--accent)' : 'var(--text-dim)',
                        fontSize: '11px',
                        fontWeight: '600',
                        cursor: 'pointer',
                        transition: 'all 0.15s'
                      }}
                    >
                      {tab}
                    </button>
                  ))}
                </div>
              </div>

              {/* Listings */}
              {filteredFindings.length === 0 ? (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '40px 0', color: 'var(--success)' }}>
                  <span style={{ fontSize: '32px', marginBottom: '10px' }}>✓</span>
                  <h4 style={{ margin: '0 0 4px 0' }}>No Vulnerabilities Identified</h4>
                  <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-muted)' }}>
                    Your code and configurations comply with checked security baselines.
                  </p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {filteredFindings.map((f, i) => {
                    const isExpanded = expanded === i;
                    const sevColor = SEV_THEME[f.severity.toUpperCase()]?.color || '#999';
                    
                    return (
                      <div 
                        key={i} 
                        style={{
                          border: '1px solid var(--border)',
                          borderRadius: '8px',
                          overflow: 'hidden',
                          background: 'var(--bg)',
                          transition: 'border-color 0.2s'
                        }}
                      >
                        <div 
                          onClick={() => setExpanded(isExpanded ? null : i)}
                          style={{
                            padding: '14px 16px',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '12px'
                          }}
                        >
                          <SeverityBadge level={f.severity} />
                          <span style={{ fontWeight: '600', fontSize: '13px', color: 'var(--text)', flex: 1 }}>
                            {f.title}
                          </span>
                          <code style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                            {f.location}
                          </code>
                          <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                            {isExpanded ? '▲' : '▼'}
                          </span>
                        </div>

                        {isExpanded && (
                          <div style={{ padding: '16px', borderTop: '1px solid var(--border)', background: 'var(--surface)' }}>
                            <div style={{ fontSize: '12px', color: 'var(--text-dim)', lineHeight: '1.6', marginBottom: '14px' }}>
                              <strong>Description:</strong> {f.description}
                            </div>

                            {/* Evidence Code Block */}
                            {f.evidence && (
                              <div style={{ marginBottom: '14px' }}>
                                <div style={{ fontSize: '10px', fontWeight: 'bold', color: 'var(--text-muted)', marginBottom: '6px', fontFamily: 'var(--mono)' }}>EVIDENCE</div>
                                <pre style={{
                                  background: 'var(--bg)',
                                  border: '1px solid var(--border)',
                                  borderRadius: '6px',
                                  padding: '12px',
                                  overflowX: 'auto',
                                  margin: 0,
                                  fontSize: '11px',
                                  fontFamily: 'var(--mono)',
                                  color: '#cbd5e1'
                                }}>
                                  <code>{f.evidence}</code>
                                </pre>
                              </div>
                            )}

                            {/* Details Grid */}
                            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '14px' }}>
                              {[['CWE ID', f.cwe_id], ['Audit Method', f.method], ['Value Trigger', f.payload]].map(([k, v]) => 
                                v && v !== 'N/A' ? (
                                  <div key={k} style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '6px', padding: '6px 12px' }}>
                                    <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>{k}</div>
                                    <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text)', marginTop: '2px' }}>{v}</div>
                                  </div>
                                ) : null
                              )}
                            </div>

                            {/* Remediation */}
                            {f.remediation && (
                              <div style={{
                                background: 'var(--success-dim)',
                                border: '1px solid var(--success)',
                                borderRadius: '8px',
                                padding: '12px 14px',
                                fontSize: '12px',
                                color: 'var(--success)',
                                lineHeight: '1.5'
                              }}>
                                <strong>🔧 Remediation:</strong> {f.remediation}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </>
          )}

        </div>
      </div>

    </div>
  );
};