import React from 'react';
import { Section } from '../components/Section';
import { CodeBlock } from '../components/CodeBlock';
import { InfoCard } from '../components/InfoCard';
import { COLORS } from '../constants/colors';

export const ArchitectureTab = () => {
  const ascii = `
┌─────────────────────────────────────────────────────────────────────────┐
│                        INTELLIGENT WEB SECURITY ANALYZER                │
│                         High-Level System Architecture                  │
└─────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │                         CLIENT LAYER                                 │
  │  ┌─────────────────────────────────────────────────────────────┐    │
  │  │  React Dashboard (Vite + TypeScript)                        │    │
  │  │  • Scan submission form  • Real-time progress (WebSocket)  │    │
  │  │  • Vulnerability charts  • Actionable report view          │    │
  │  └───────────────────────────┬─────────────────────────────────┘    │
  └──────────────────────────────┼───────────────────────────────────────┘
                                 │ HTTPS / WSS
  ┌──────────────────────────────▼───────────────────────────────────────┐
  │                         API GATEWAY (Nginx)                          │
  │            Rate Limiting · JWT Auth · TLS Termination               │
  └──────┬──────────────────────────────────────────────┬───────────────┘
         │ REST / GraphQL                               │ WebSocket
  ┌──────▼──────────────┐                     ┌────────▼──────────────┐
  │  FastAPI App Server │                     │  WebSocket Server     │
  │  • /api/scans       │                     │  Progress Updates     │
  │  • /api/reports     │                     │  Live Log Streaming   │
  │  • /api/users       │                     └───────────────────────┘
  └──────┬──────────────┘
         │ Enqueue Job
  ┌──────▼───────────────────────────────────────────────────────────────┐
  │                      TASK QUEUE (Celery + Redis)                     │
  │   ┌────────────────────────────────────────────────────────────┐    │
  │   │  Scan Orchestrator — routes jobs to scanner workers        │    │
  │   └──────┬─────────────────────────────────────────────────────┘    │
  └──────────┼───────────────────────────────────────────────────────────┘
             │ Fan-out to scanner workers
  ┌──────────▼───────────────────────────────────────────────────────────┐
  │                       SCANNER MODULES LAYER                          │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────┐ │
  │  │  XSS Scanner │  │  SQLi Scanner│  │ CSRF Scanner │  │  SSRF   │ │
  │  │  Rule-based  │  │  ML + Regex  │  │ Token Check  │  │  HDR    │ │
  │  │  + DOM parse │  │  + Payload   │  │ + SameSite   │  │  Scan   │ │
  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └────┬────┘ │
  └─────────┼─────────────────┼─────────────────┼───────────────┼──────┘
            │                 │                 │               │
  ┌─────────▼─────────────────▼─────────────────▼───────────────▼──────┐
  │                     ML / AI ENGINE LAYER                            │
  │  ┌──────────────────┐   ┌────────────────────────────────────────┐ │
  │  │  Feature Extractor│   │  Classifier (Scikit-learn / XGBoost)  │ │
  │  │  HTTP req/res     │   │  Anomaly Detection (IsolationForest)  │ │
  │  │  URL patterns     │   │  Confidence Score → False Pos filter  │ │
  │  └──────────────────┘   └────────────────────────────────────────┘ │
  │  ┌────────────────────────────────────────────────────────────────┐ │
  │  │  NLP Report Generator (Hugging Face / LLM API)                │ │
  │  │  Raw findings → Plain English Summary + Remediation Steps     │ │
  │  └────────────────────────────────────────────────────────────────┘ │
  └─────────────────────────────────────┬───────────────────────────────┘
                                         │
  ┌──────────────────────────────────────▼──────────────────────────────┐
  │                         DATA LAYER                                   │
  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
  │  │  PostgreSQL       │  │  Redis Cache     │  │  MinIO / S3      │  │
  │  │  Scans, Reports   │  │  Session, Queue  │  │  Raw Payloads    │  │
  │  │  Users, Vulns     │  │  Rate Limits     │  │  ML Artifacts    │  │
  │  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
  └──────────────────────────────────────────────────────────────────────┘
`;
  return (
    <div>
      <Section title="System Architecture Overview" accent={COLORS.accent}>
        <p style={{ color: COLORS.textDim, lineHeight: 1.7, marginBottom: 16 }}>
          A six-layer, event-driven architecture designed for concurrent scanning, AI-augmented detection, and NLP-powered reporting. Each layer is independently scalable.
        </p>
        <CodeBlock code={ascii.trim()} lang="ascii" />
      </Section>

      <Section title="Component Breakdown" accent={COLORS.info}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <InfoCard icon="⚛️" title="CLIENT LAYER" accent={COLORS.accent} items={[
            "React 18 + TypeScript + Vite for fast builds",
            "Recharts / D3.js for vulnerability visualizations",
            "WebSocket client for real-time scan progress",
            "JWT-based auth with refresh token rotation",
            "Tailwind CSS for responsive layout"
          ]} />
          <InfoCard icon="⚡" title="API GATEWAY" accent={COLORS.info} items={[
            "Nginx as reverse proxy + TLS terminator",
            "Rate limiting: 10 scans/hour per user",
            "JWT validation at gateway level",
            "Request/response logging to ELK Stack",
            "CORS policy enforcement"
          ]} />
          <InfoCard icon="🔄" title="TASK QUEUE" accent={COLORS.warn} items={[
            "Celery + Redis Broker for async job dispatch",
            "Fan-out pattern: one scan → N parallel workers",
            "Job priority queues (high/medium/low)",
            "Dead letter queue for failed scans",
            "Result TTL: 24h in Redis, permanent in PostgreSQL"
          ]} />
          <InfoCard icon="🧠" title="ML / AI ENGINE" accent={COLORS.success} items={[
            "XGBoost classifier for vuln type detection",
            "IsolationForest for anomaly / 0-day signals",
            "Feature engineering from HTTP req/res pairs",
            "Model versioning with MLflow",
            "NLP: GPT-4o API or fine-tuned Mistral for reports"
          ]} />
        </div>
      </Section>

      <Section title="Data Flow — Scan Lifecycle" accent={COLORS.success}>
        <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 20 }}>
          {[
            ["1", "User submits URL + config via React form", COLORS.accent],
            ["2", "FastAPI validates input, creates scan record in PostgreSQL, returns scan_id", COLORS.info],
            ["3", "Celery dispatches scan job; WebSocket emits status: QUEUED", COLORS.warn],
            ["4", "Scanner workers fan out: XSS, SQLi, CSRF workers run in parallel", COLORS.warn],
            ["5", "Each worker fetches target URL, injects payloads, records HTTP responses", COLORS.warn],
            ["6", "ML Engine scores each candidate finding (0–1 confidence)", COLORS.success],
            ["7", "High-confidence findings passed to NLP module for report generation", COLORS.success],
            ["8", "Aggregated results written to PostgreSQL; WebSocket emits COMPLETE", COLORS.success],
            ["9", "React dashboard renders interactive report with severity breakdown", COLORS.accent],
          ].map(([num, text, color]) => (
            <div key={num} style={{ display: "flex", alignItems: "flex-start", gap: 16, marginBottom: 14 }}>
              <div style={{ width: 28, height: 28, borderRadius: "50%", background: color + "22", border: `2px solid ${color}`, color, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 800, flexShrink: 0 }}>{num}</div>
              <span style={{ color: COLORS.textDim, fontSize: 14, lineHeight: 1.6, paddingTop: 4 }}>{text}</span>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
};