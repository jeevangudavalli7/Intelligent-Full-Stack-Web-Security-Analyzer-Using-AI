// frontend/src/pages/LoginPage.jsx  — NEW FILE (create folder src/pages/ then this file)
import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

export default function LoginPage() {
  const { login } = useAuth();
  const { theme, toggle } = useTheme();
  const [mode,      setMode]      = useState('login');
  const [email,     setEmail]     = useState('');
  const [password,  setPassword]  = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [error,     setError]     = useState('');
  const [loading,   setLoading]   = useState(false);
  const [showPw,    setShowPw]    = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    if (mode === 'register' && password !== confirmPw) {
      setError('Passwords do not match.'); return;
    }
    setLoading(true);
    try {
      const endpoint = mode === 'login'
        ? '/api/v1/auth/login'
        : '/api/v1/auth/register';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Authentication failed');
      if (mode === 'login') {
        login({ email }, data.access_token);
      } else {
        setMode('login'); setPassword(''); setError('');
      }
    } catch (err) {
      // If backend is offline, fall back to demo mode automatically
      if (err.message.toLowerCase().includes('fetch') || err.message.includes('NetworkError') || err.message.includes('Failed to fetch')) {
        login({ email: email || 'demo@security.ai' }, 'demo-token');
      } else {
        setError(err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  const demoLogin = () => login({ email: 'demo@security.ai' }, 'demo-token');

  const inputStyle = {
    width: '100%', padding: '12px 14px',
    background: 'var(--input-bg)',
    border: '1px solid var(--border)',
    borderRadius: 10, color: 'var(--text)',
    fontSize: 14, fontFamily: 'var(--sans)',
    outline: 'none', transition: 'border 0.2s',
  };
  const labelStyle = {
    display: 'block', fontSize: 11,
    color: 'var(--text-muted)', marginBottom: 7,
    fontFamily: 'var(--mono)', letterSpacing: 1.5,
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '2rem', position: 'relative', overflow: 'hidden' }}>

      {/* Glow blobs */}
      <div style={{ position: 'fixed', top: '-20%', right: '-10%', width: 500, height: 500, borderRadius: '50%', background: 'radial-gradient(circle, var(--accent-glow) 0%, transparent 70%)', pointerEvents: 'none' }} />
      <div style={{ position: 'fixed', bottom: '-15%', left: '-8%', width: 400, height: 400, borderRadius: '50%', background: 'radial-gradient(circle, var(--info-dim) 0%, transparent 70%)', pointerEvents: 'none' }} />

      {/* Theme toggle */}
      <button onClick={toggle}
        style={{ position: 'fixed', top: 20, right: 20, background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 10, padding: '8px 14px', cursor: 'pointer', color: 'var(--text-dim)', fontSize: 12, fontFamily: 'var(--mono)', display: 'flex', alignItems: 'center', gap: 7, zIndex: 100 }}>
        {theme === 'dark' ? '☀ Light' : '◑ Dark'}
      </button>

      {/* Card */}
      <div className="fade-up" style={{ width: '100%', maxWidth: 440, background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 18, padding: '2.5rem', position: 'relative', zIndex: 1 }}>

        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{ width: 52, height: 52, borderRadius: 14, background: 'linear-gradient(135deg, var(--accent), var(--info))', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24, margin: '0 auto 1rem', boxShadow: '0 0 30px var(--accent-glow)' }}>🛡</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 4, textTransform: 'uppercase', marginBottom: 6 }}>Security Analyzer</div>
          <h1 style={{ fontSize: 22, fontWeight: 600, color: 'var(--text)', fontFamily: 'var(--sans)' }}>
            {mode === 'login' ? 'Welcome back' : 'Create account'}
          </h1>
          <p style={{ color: 'var(--text-dim)', fontSize: 13, marginTop: 4 }}>
            {mode === 'login' ? 'Sign in to your security dashboard' : 'Start scanning vulnerabilities today'}
          </p>
        </div>

        {/* Mode pills */}
        <div style={{ display: 'flex', background: 'var(--surface)', borderRadius: 10, padding: 3, marginBottom: '1.5rem', border: '1px solid var(--border)' }}>
          {['login', 'register'].map(m => (
            <button key={m} onClick={() => { setMode(m); setError(''); }}
              style={{ flex: 1, padding: '8px', border: 'none', borderRadius: 8, cursor: 'pointer', fontSize: 13, fontWeight: 500, fontFamily: 'var(--sans)', transition: 'all 0.2s', background: mode === m ? 'var(--accent)' : 'transparent', color: mode === m ? '#000' : 'var(--text-dim)' }}>
              {m === 'login' ? 'Sign In' : 'Register'}
            </button>
          ))}
        </div>

        {/* Form */}
        <form onSubmit={submit}>
          <div style={{ marginBottom: '1rem' }}>
            <label style={labelStyle}>EMAIL</label>
            <input type="email" required value={email} onChange={e => setEmail(e.target.value)}
              placeholder="you@company.com" style={inputStyle}
              onFocus={e => e.target.style.borderColor = 'var(--accent)'}
              onBlur={e => e.target.style.borderColor = 'var(--border)'} />
          </div>

          <div style={{ marginBottom: mode === 'register' ? '1rem' : '1.5rem' }}>
            <label style={labelStyle}>PASSWORD</label>
            <div style={{ position: 'relative' }}>
              <input type={showPw ? 'text' : 'password'} required value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Min. 8 characters"
                style={{ ...inputStyle, paddingRight: 44 }}
                onFocus={e => e.target.style.borderColor = 'var(--accent)'}
                onBlur={e => e.target.style.borderColor = 'var(--border)'} />
              <button type="button" onClick={() => setShowPw(p => !p)}
                style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 16 }}>
                {showPw ? '🙈' : '👁'}
              </button>
            </div>
          </div>

          {mode === 'register' && (
            <div style={{ marginBottom: '1.5rem' }}>
              <label style={labelStyle}>CONFIRM PASSWORD</label>
              <input type={showPw ? 'text' : 'password'} required value={confirmPw}
                onChange={e => setConfirmPw(e.target.value)}
                placeholder="Repeat password"
                style={{ ...inputStyle, borderColor: confirmPw && confirmPw !== password ? 'var(--danger)' : 'var(--border)' }} />
            </div>
          )}

          {error && (
            <div style={{ marginBottom: '1rem', padding: '10px 14px', background: 'var(--danger-dim)', border: '1px solid var(--danger)', borderRadius: 8, color: 'var(--danger)', fontSize: 13 }}>
              ⚠ {error}
            </div>
          )}

          <button type="submit" disabled={loading}
            style={{ width: '100%', padding: '13px', background: loading ? 'var(--text-muted)' : 'var(--accent)', color: '#000', border: 'none', borderRadius: 10, fontSize: 14, fontWeight: 600, cursor: loading ? 'not-allowed' : 'pointer', fontFamily: 'var(--sans)', transition: 'all 0.2s', boxShadow: loading ? 'none' : '0 0 20px var(--accent-glow)' }}>
            {loading ? 'Processing...' : mode === 'login' ? 'Sign In →' : 'Create Account →'}
          </button>
        </form>

        {/* Divider */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '1.25rem 0' }}>
          <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
          <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>or</span>
          <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
        </div>

        <button onClick={demoLogin}
          style={{ width: '100%', padding: '12px', background: 'transparent', border: '1px solid var(--border)', borderRadius: 10, color: 'var(--text-dim)', fontSize: 13, cursor: 'pointer', fontFamily: 'var(--mono)', transition: 'all 0.2s' }}
          onMouseEnter={e => { e.target.style.borderColor = 'var(--accent)'; e.target.style.color = 'var(--accent)'; }}
          onMouseLeave={e => { e.target.style.borderColor = 'var(--border)'; e.target.style.color = 'var(--text-dim)'; }}>
          ▶  Continue as Demo User
        </button>

        <p style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 11, marginTop: '1.5rem' }}>
          AI-powered vulnerability scanner · MIT License
        </p>
      </div>
    </div>
  );
}