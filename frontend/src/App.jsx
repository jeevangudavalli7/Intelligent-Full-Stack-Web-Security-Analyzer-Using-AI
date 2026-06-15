// frontend/src/App.jsx  — REPLACE your existing file entirely with this
import React, { useState } from 'react';
import { useAuth } from './context/AuthContext';
import { useTheme } from './context/ThemeContext';

// Pages
import LoginPage from './pages/LoginPage';

// Tab components (unchanged except DemoTab)
import { DemoTab }         from './tabs/DemoTab';
import { ArchitectureTab } from './tabs/ArchitectureTab';
import { ScannerTab }      from './tabs/ScannerTab';
import { MLTab }           from './tabs/MLTab';
import { APITab }          from './tabs/APITab';
import { SchemaTab }       from './tabs/SchemaTab';
import { DeployTab }       from './tabs/DeployTab';

const TABS = [
  { id: 'demo',         label: 'Live Demo',       icon: '▶' },
  { id: 'architecture', label: 'Architecture',    icon: '🏗' },
  { id: 'scanner',      label: 'Scanner Modules', icon: '🔍' },
  { id: 'ml',           label: 'ML Pipeline',     icon: '🧠' },
  { id: 'api',          label: 'API Endpoints',   icon: '⚡' },
  { id: 'schema',       label: 'DB Schema',       icon: '🗄' },
  { id: 'deploy',       label: 'Deployment',      icon: '🚀' },
];

function App() {
  const { user, logout } = useAuth();
  const { theme, toggle } = useTheme();
  const [activeTab, setActiveTab] = useState('demo');

  // ── Not logged in → show login page ───────────────────────────────────────
  if (!user) return <LoginPage />;

  // ── Logged in → show main app ──────────────────────────────────────────────
  return (
    <div style={{ background: 'var(--bg)', minHeight: '100vh', position: 'relative' }}>

      {/* ── NAVBAR ── */}
      <header style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)', position: 'sticky', top: 0, zIndex: 50 }}>
        <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 28px' }}>

          {/* Top bar */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, height: 58 }}>
            {/* Brand */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: 'linear-gradient(135deg, var(--accent), var(--info))', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16, boxShadow: '0 0 16px var(--accent-glow)' }}>🛡</div>
              <div>
                <div style={{ fontFamily: 'var(--mono)', fontWeight: 700, fontSize: 13, color: 'var(--text)' }}>SecurityAI</div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 2 }}>ANALYZER v2</div>
              </div>
            </div>

            <div style={{ flex: 1 }} />

            {/* Tech badges */}
            <div style={{ display: 'flex', gap: 6 }}>
              {['XSS','SQLi','CSRF','ML','NLP'].map(b => (
                <span key={b} style={{ background: 'var(--accent-glow)', color: 'var(--accent)', border: '1px solid rgba(34,211,238,0.25)', borderRadius: 4, padding: '2px 8px', fontSize: 10, fontFamily: 'var(--mono)', fontWeight: 700, letterSpacing: 1 }}>{b}</span>
              ))}
            </div>

            {/* Dark / Light toggle */}
            <button onClick={toggle}
              style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, padding: '7px 13px', cursor: 'pointer', color: 'var(--text-dim)', fontSize: 12, fontFamily: 'var(--mono)', display: 'flex', alignItems: 'center', gap: 6, transition: 'border 0.2s' }}
              onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--accent)'}
              onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}>
              {theme === 'dark' ? '☀ Light' : '◑ Dark'}
            </button>

            {/* User avatar + logout */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 30, height: 30, borderRadius: '50%', background: 'var(--accent-glow)', border: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: 'var(--accent)', fontWeight: 700, fontFamily: 'var(--mono)' }}>
                {(user.email || 'U')[0].toUpperCase()}
              </div>
              <span style={{ fontSize: 12, color: 'var(--text-dim)', fontFamily: 'var(--mono)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {user.email}
              </span>
              <button onClick={logout}
                style={{ background: 'transparent', border: '1px solid var(--border)', borderRadius: 7, padding: '6px 12px', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--mono)', transition: 'all 0.2s' }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--danger)'; e.currentTarget.style.color = 'var(--danger)'; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)'; }}>
                Sign Out
              </button>
            </div>
          </div>

          {/* Tab bar */}
          <div style={{ display: 'flex', gap: 2 }}>
            {TABS.map(tab => (
              <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                style={{ background: 'transparent', border: 'none', borderBottom: activeTab === tab.id ? '2px solid var(--accent)' : '2px solid transparent', color: activeTab === tab.id ? 'var(--accent)' : 'var(--text-muted)', padding: '10px 15px', fontSize: 13, cursor: 'pointer', borderRadius: '6px 6px 0 0', fontWeight: activeTab === tab.id ? 600 : 400, fontFamily: 'var(--sans)', transition: 'all 0.15s', display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}
                onMouseEnter={e => { if (activeTab !== tab.id) e.currentTarget.style.color = 'var(--text)'; }}
                onMouseLeave={e => { if (activeTab !== tab.id) e.currentTarget.style.color = 'var(--text-muted)'; }}>
                <span>{tab.icon}</span>{tab.label}
              </button>
            ))}
          </div>
        </div>
      </header>

      {/* ── PAGE CONTENT ── */}
      <main style={{ maxWidth: 1280, margin: '0 auto', padding: '32px 28px', position: 'relative', zIndex: 1 }}>
        {activeTab === 'demo'         && <DemoTab />}
        {activeTab === 'architecture' && <ArchitectureTab />}
        {activeTab === 'scanner'      && <ScannerTab />}
        {activeTab === 'ml'           && <MLTab />}
        {activeTab === 'api'          && <APITab />}
        {activeTab === 'schema'       && <SchemaTab />}
        {activeTab === 'deploy'       && <DeployTab />}
      </main>
    </div>
  );
}

export default App;