import React, { useState } from 'react';
import { COLORS } from './constants/colors';
import { Badge } from './components/Badge';
// Import all tabs
import { ArchitectureTab } from './tabs/ArchitectureTab';
import { ScannerTab } from './tabs/ScannerTab';
import { MLTab } from './tabs/MLTab';
import { APITab } from './tabs/APITab';
import { SchemaTab } from './tabs/SchemaTab';
import { DeployTab } from './tabs/DeployTab';
import { DemoTab } from './tabs/DemoTab';

const TAB_DEMO = "demo";
const TAB_ARCHITECTURE = "architecture";
const TAB_SCANNER = "scanner";
const TAB_ML = "ml";
const TAB_API = "api";
const TAB_SCHEMA = "schema";
const TAB_DEPLOY = "deploy";

function App() {
  const [activeTab, setActiveTab] = useState(TAB_DEMO);

  const TABS = [
    { id: TAB_DEMO, label: "Live Demo", icon: "▶" },
    { id: TAB_ARCHITECTURE, label: "Architecture", icon: "🏗" },
    { id: TAB_SCANNER, label: "Scanner Modules", icon: "🔍" },
    { id: TAB_ML, label: "ML Pipeline", icon: "🧠" },
    { id: TAB_API, label: "API Endpoints", icon: "⚡" },
    { id: TAB_SCHEMA, label: "DB Schema", icon: "🗄" },
    { id: TAB_DEPLOY, label: "Deployment", icon: "🚀" },
  ];

  return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", fontFamily: "'Segoe UI', system-ui, sans-serif", color: COLORS.text }}>
      <div style={{ background: COLORS.surface, borderBottom: `1px solid ${COLORS.border}`, padding: "0 32px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "20px 0 16px" }}>
            <div style={{ width: 36, height: 36, background: `linear-gradient(135deg, ${COLORS.accent}, ${COLORS.info})`, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>🛡</div>
            <div>
              <div style={{ color: COLORS.text, fontWeight: 800, fontSize: 18, letterSpacing: -0.5 }}>Intelligent Web Security Analyzer</div>
              <div style={{ color: COLORS.muted, fontSize: 12 }}>Full-Stack · AI/ML Powered · NLP Reports</div>
            </div>
            <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
              <Badge label="XSS" color={COLORS.danger} />
              <Badge label="SQLi" color={COLORS.warn} />
              <Badge label="CSRF" color={COLORS.info} />
              <Badge label="ML" color={COLORS.success} />
              <Badge label="NLP" color="#f06292" />
            </div>
          </div>
          <div style={{ display: "flex", gap: 2 }}>
            {TABS.map(tab => (
              <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                style={{ background: activeTab === tab.id ? COLORS.card : "transparent", border: "none", borderBottom: activeTab === tab.id ? `2px solid ${COLORS.accent}` : "2px solid transparent", color: activeTab === tab.id ? COLORS.text : COLORS.muted, padding: "10px 16px", fontSize: 13, cursor: "pointer", borderRadius: "6px 6px 0 0", fontWeight: activeTab === tab.id ? 700 : 400, transition: "all 0.15s" }}>
                <span style={{ marginRight: 6 }}>{tab.icon}</span>{tab.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "32px" }}>
        {activeTab === TAB_DEMO && <DemoTab />}
        {activeTab === TAB_ARCHITECTURE && <ArchitectureTab />}
        {activeTab === TAB_SCANNER && <ScannerTab />}
        {activeTab === TAB_ML && <MLTab />}
        {activeTab === TAB_API && <APITab />}
        {activeTab === TAB_SCHEMA && <SchemaTab />}
        {activeTab === TAB_DEPLOY && <DeployTab />}
      </div>
    </div>
  );
}

export default App;