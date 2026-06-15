// frontend/src/components/Navbar.jsx
import React from 'react';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';

export function Navbar({ activeTab, setActiveTab, tabs }) {
  const { theme, toggle } = useTheme();
  const { user, logout } = useAuth();

  return (
    <header style={{
      background: 'var(--surface)',
      borderBottom: '1px solid var(--border)',
      position: 'sticky', top: 0, zIndex: 50,
    }}>
      {/* Top bar */}
      <div style={{
        maxWidth: 1280, margin: '0 auto',
        padding: '0 24px',
        display: 'flex', alignItems: 'center', gap: 16,
        height: 60,
      }}>
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: 'linear-gradient(135deg, var(--accent), var(--info))',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 16, boxShadow: '0 0 16px var(--accent-glow)',
          }}>🛡</div>
          <div>
            <div style={{ fontFamily: 'var(--mono)', fontWeight: 700, fontSize: 13, color: 'var(--text)', letterSpacing: -0.3 }}>
              SecurityAI
            </div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 2 }}>
              ANALYZER v2
            </div>
          </div>
        </div>

        {/* Spacer */}
        <div style={{ flex: 1 }} />

        {/* Badges */}
        <div style={{ display: 'flex', gap: 6 }}>
          {['XSS', 'SQLi', 'CSRF', 'ML', 'NLP'].map(b => (
            <span key={b} style={{
              background: 'var(--accent-glow)',
              color: 'var(--accent)',
              border: '1px solid rgba(34,211,238,0.3)',
              borderRadius: 4, padding: '2px 8px',
              fontSize: 10, fontFamily: 'var(--mono)', fontWeight: 700, letterSpacing: 1,
            }}>{b}</span>
          ))}
        </div>

        {/* Theme toggle */}
        <button onClick={toggle} title={theme === 'dark' ? 'Switch to Light' : 'Switch to Dark'}
          style={{
            background: 'var(--card)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '7px 12px',
            cursor: 'pointer', color: 'var(--text-dim)',
            fontSize: 12, fontFamily: 'var(--mono)',
            display: 'flex', alignItems: 'center', gap: 6,
            transition: 'all 0.2s',
          }}
          onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--accent)'}
          onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
        >
          {theme === 'dark' ? '☀ Light' : '◑ Dark'}
        </button>

        {/* User + Logout */}
        {user && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: '50%',
              background: 'var(--accent-glow)',
              border: '1px solid var(--border-light)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 13, color: 'var(--accent)', fontWeight: 700, fontFamily: 'var(--mono)',
            }}>
              {(user.email || 'U')[0].toUpperCase()}
            </div>
            <button onClick={logout}
              style={{
                background: 'transparent', border: '1px solid var(--border)',
                borderRadius: 8, padding: '7px 12px',
                cursor: 'pointer', color: 'var(--text-muted)',
                fontSize: 12, fontFamily: 'var(--mono)',
                transition: 'all 0.2s',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--danger)'; e.currentTarget.style.color = 'var(--danger)'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)'; }}
            >
              Sign Out
            </button>
          </div>
        )}
      </div>

      {/* Tab nav */}
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', display: 'flex', gap: 2 }}>
        {tabs.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            style={{
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === tab.id
                ? '2px solid var(--accent)'
                : '2px solid transparent',
              color: activeTab === tab.id ? 'var(--accent)' : 'var(--text-muted)',
              padding: '11px 16px',
              fontSize: 13, cursor: 'pointer',
              borderRadius: '6px 6px 0 0',
              fontWeight: activeTab === tab.id ? 600 : 400,
              fontFamily: 'var(--sans)',
              transition: 'all 0.15s',
              display: 'flex', alignItems: 'center', gap: 7,
              whiteSpace: 'nowrap',
            }}
            onMouseEnter={e => { if (activeTab !== tab.id) e.currentTarget.style.color = 'var(--text)'; }}
            onMouseLeave={e => { if (activeTab !== tab.id) e.currentTarget.style.color = 'var(--text-muted)'; }}
          >
            <span style={{ fontSize: 15 }}>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>
    </header>
  );
}