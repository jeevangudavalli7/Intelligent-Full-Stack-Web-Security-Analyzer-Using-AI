import React from 'react';
import { Section } from '../components/Section';
import { CodeBlock } from '../components/CodeBlock';
import { COLORS } from '../constants/colors';

export const DeployTab = () => {
  const dockerCompose = `# docker-compose.yml — Local Development Stack
version: "3.9"
services:

  # ── Frontend ──────────────────────────────────────────────
  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    environment:
      VITE_API_URL: http://localhost:8000
      VITE_WS_URL: ws://localhost:8001

  # ── API Server ────────────────────────────────────────────
  api:
    build: ./backend
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
    ports: ["8000:8000"]
    environment:
      DATABASE_URL: postgresql://user:pass@postgres:5432/secanalyzer
      REDIS_URL: redis://redis:6379/0
      SECRET_KEY: \${SECRET_KEY}
      ANTHROPIC_API_KEY: \${ANTHROPIC_API_KEY}
      MLFLOW_TRACKING_URI: http://mlflow:5000
    depends_on: [postgres, redis]

  # ── WebSocket Server ──────────────────────────────────────
  ws_server:
    build: ./backend
    command: python ws_server.py
    ports: ["8001:8001"]
    environment:
      REDIS_URL: redis://redis:6379/0

  # ── Celery Workers (XSS + SQLi scanners) ─────────────────
  worker_passive:
    build: ./backend
    command: celery -A celery_app worker -Q scans-passive -c 4 --loglevel=info
    environment:
      REDIS_URL: redis://redis:6379/0
      DATABASE_URL: postgresql://user:pass@postgres:5432/secanalyzer

  worker_active:
    build: ./backend
    command: celery -A celery_app worker -Q scans-active -c 2 --loglevel=info
    environment:
      REDIS_URL: redis://redis:6379/0
      DATABASE_URL: postgresql://user:pass@postgres:5432/secanalyzer

  # ── Celery Flower (monitoring) ────────────────────────────
  flower:
    build: ./backend
    command: celery -A celery_app flower --port=5555
    ports: ["5555:5555"]

  # ── Databases ─────────────────────────────────────────────
  postgres:
    image: postgres:16-alpine
    volumes: [pgdata:/var/lib/postgresql/data]
    environment:
      POSTGRES_DB: secanalyzer
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass

  redis:
    image: redis:7-alpine
    volumes: [redisdata:/data]

  # ── ML Tracking ───────────────────────────────────────────
  mlflow:
    image: ghcr.io/mlflow/mlflow:v2.14.1
    ports: ["5000:5000"]
    command: mlflow server --host 0.0.0.0 --backend-store-uri postgresql://...
    volumes: [mlflow_artifacts:/mlflow/artifacts]

  # ── Object Storage (ML models + raw payloads) ─────────────
  minio:
    image: minio/minio
    ports: ["9000:9000", "9001:9001"]
    command: server /data --console-address ":9001"

volumes:
  pgdata: redisdata: mlflow_artifacts:`;

  const k8s = `# k8s/deployment.yaml — Kubernetes (Production)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-analyzer-api
  namespace: secanalyzer
spec:
  replicas: 3                        # Horizontal scaling
  selector:
    matchLabels: { app: api }
  template:
    spec:
      containers:
      - name: api
        image: secanalyzer/api:v1.2.3
        resources:
          requests: { cpu: "500m", memory: "512Mi" }
          limits:   { cpu: "2000m", memory: "2Gi" }
        readinessProbe:
          httpGet: { path: /health, port: 8000 }
          initialDelaySeconds: 10
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef: { name: db-secret, key: url }
---
# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: security-analyzer-api
  minReplicas: 2
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target: { type: Utilization, averageUtilization: 70 }`;

  return (
    <div>
      <Section title="Docker Compose — Local Dev">
        <CodeBlock code={dockerCompose} lang="yaml" />
      </Section>
      <Section title="Kubernetes — Production" accent={COLORS.info}>
        <CodeBlock code={k8s} lang="yaml" />
      </Section>
      <Section title="CI/CD Pipeline" accent={COLORS.success}>
        <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 20 }}>
          {[
            ["Push to branch", "GitHub Actions triggered", COLORS.accent],
            ["Lint + Unit tests", "pytest, eslint, mypy type checks", COLORS.info],
            ["Security scan", "Trivy container scan + SAST with Semgrep", COLORS.warn],
            ["Build Docker images", "Multi-stage builds, pushed to ECR/GHCR", COLORS.warn],
            ["Integration tests", "Spin up compose stack, run API tests", COLORS.warn],
            ["ML model validation", "Run inference tests on holdout set (AUC ≥ 0.92)", COLORS.success],
            ["Deploy to staging", "Helm upgrade --install secanalyzer-staging", COLORS.success],
            ["Smoke tests", "E2E Playwright tests against staging", COLORS.success],
            ["Deploy to prod", "Blue/green deployment via Argo CD", COLORS.accent],
          ].map(([step, detail, color], i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: color, flexShrink: 0 }} />
              <span style={{ color: COLORS.text, fontSize: 13, minWidth: 180 }}>{step}</span>
              <span style={{ color: COLORS.muted, fontSize: 12 }}>{detail}</span>
            </div>
          ))}
        </div>
      </Section>
      <Section title="Monitoring Stack" accent={COLORS.warn}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
          {[
            { tool: "Prometheus", purpose: "Metrics collection", metrics: "scan duration, queue depth, error rates, ML inference latency" },
            { tool: "Grafana", purpose: "Dashboards & alerting", metrics: "Real-time scan throughput, worker health, vulnerability trends" },
            { tool: "ELK Stack", purpose: "Log aggregation", metrics: "API request logs, scanner debug output, security events" },
            { tool: "Sentry", purpose: "Error tracking", metrics: "Backend exceptions, unhandled errors, performance traces" },
            { tool: "MLflow", purpose: "ML experiment tracking", metrics: "Model metrics, artifact versions, training runs" },
            { tool: "PagerDuty", purpose: "Incident management", metrics: "On-call routing, escalation policies, runbooks" },
          ].map(m => (
            <div key={m.tool} style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 14 }}>
              <div style={{ color: COLORS.accent, fontWeight: 700, fontSize: 13, marginBottom: 4 }}>{m.tool}</div>
              <div style={{ color: COLORS.text, fontSize: 12, marginBottom: 6 }}>{m.purpose}</div>
              <div style={{ color: COLORS.muted, fontSize: 11 }}>{m.metrics}</div>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
};