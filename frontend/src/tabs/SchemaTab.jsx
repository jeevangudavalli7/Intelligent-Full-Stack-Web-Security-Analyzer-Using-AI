import React from 'react';
import { Section } from '../components/Section';
import { CodeBlock } from '../components/CodeBlock';
import { COLORS } from '../constants/colors';

export const SchemaTab = () => {
  const schema = `-- PostgreSQL Schema

-- Users
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    role        VARCHAR(20) DEFAULT 'user',  -- user | admin
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_login  TIMESTAMPTZ
);

-- Scans
CREATE TABLE scans (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
    target_url   TEXT NOT NULL,
    mode         VARCHAR(10) NOT NULL,        -- passive | active
    intensity    SMALLINT DEFAULT 1,
    modules      TEXT[],                       -- {xss, sqli, csrf, ...}
    status       VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED|RUNNING|COMPLETE|FAILED
    progress_pct SMALLINT DEFAULT 0,
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    error_msg    TEXT,
    risk_score   NUMERIC(4,2)                 -- 0.00 – 10.00
);

CREATE INDEX idx_scans_user ON scans(user_id, created_at DESC);
CREATE INDEX idx_scans_status ON scans(status) WHERE status IN ('QUEUED','RUNNING');

-- Findings (individual vulnerabilities)
CREATE TABLE findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      UUID REFERENCES scans(id) ON DELETE CASCADE,
    vuln_type    VARCHAR(50) NOT NULL,          -- XSS | SQLi | CSRF | ...
    severity     VARCHAR(10) NOT NULL,          -- CRITICAL|HIGH|MEDIUM|LOW|INFO
    url          TEXT NOT NULL,
    parameter    VARCHAR(255),
    payload      TEXT,
    evidence     TEXT,
    confidence   NUMERIC(4,3),                  -- ML confidence 0.000-1.000
    is_false_pos BOOLEAN DEFAULT FALSE,
    is_verified  BOOLEAN DEFAULT FALSE,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_type ON findings(vuln_type, severity);

-- AI-generated report sections
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID REFERENCES scans(id) UNIQUE,
    executive_summary TEXT,
    total_critical  SMALLINT DEFAULT 0,
    total_high      SMALLINT DEFAULT 0,
    total_medium    SMALLINT DEFAULT 0,
    total_low       SMALLINT DEFAULT 0,
    total_info      SMALLINT DEFAULT 0,
    nlp_model_ver   VARCHAR(50),
    generated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Per-finding NLP enrichment
CREATE TABLE finding_insights (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID REFERENCES findings(id) ON DELETE CASCADE,
    plain_english   TEXT,         -- "This XSS allows attackers to steal cookies..."
    business_impact TEXT,
    remediation     TEXT,
    code_example    TEXT,
    references      TEXT[],       -- ['CWE-79', 'OWASP A03:2021']
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ML Model registry
CREATE TABLE model_versions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(100) NOT NULL,  -- sqli_xgb, xss_rf, ...
    version       VARCHAR(20) NOT NULL,
    artifact_path TEXT,                   -- S3 / MinIO path
    roc_auc       NUMERIC(5,4),
    f1_score      NUMERIC(5,4),
    deployed_at   TIMESTAMPTZ,
    is_active     BOOLEAN DEFAULT FALSE,
    trained_on    JSONB                   -- metadata: dataset size, features used
);

-- Audit log
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID REFERENCES users(id),
    action     VARCHAR(100) NOT NULL,
    resource   VARCHAR(100),
    ip_addr    INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);`;

  return (
    <div>
      <Section title="PostgreSQL Database Schema">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 24 }}>
          {[
            { table: "users", cols: 8, purpose: "Authentication & authorization", icon: "👤" },
            { table: "scans", cols: 13, purpose: "Scan jobs & status tracking", icon: "🔍" },
            { table: "findings", cols: 12, purpose: "Individual vulnerability records", icon: "⚠️" },
            { table: "reports", cols: 9, purpose: "Aggregated NLP-generated reports", icon: "📋" },
            { table: "finding_insights", cols: 7, purpose: "Per-finding AI explanations", icon: "🧠" },
            { table: "model_versions", cols: 9, purpose: "ML model registry & versioning", icon: "🤖" },
          ].map(t => (
            <div key={t.table} style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 16 }}>
              <div style={{ fontSize: 20, marginBottom: 6 }}>{t.icon}</div>
              <div style={{ color: COLORS.accent, fontFamily: "monospace", fontWeight: 700, fontSize: 13 }}>{t.table}</div>
              <div style={{ color: COLORS.muted, fontSize: 11, marginBottom: 6 }}>{t.cols} columns</div>
              <div style={{ color: COLORS.textDim, fontSize: 12 }}>{t.purpose}</div>
            </div>
          ))}
        </div>
        <CodeBlock code={schema} lang="sql" />
      </Section>
    </div>
  );
};