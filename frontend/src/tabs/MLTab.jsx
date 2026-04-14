import React from 'react';
import { Section } from '../components/Section';
import { CodeBlock } from '../components/CodeBlock';
import { COLORS } from '../constants/colors';

export const MLTab = () => {
  const pipelineCode = `# ml/pipeline.py — Full ML Training Pipeline
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, roc_auc_score
import mlflow, mlflow.sklearn
import joblib

# ── 1. DATA COLLECTION ──────────────────────────────────────────────────────
# Public datasets:
#   • NVD CVE database (NIST)
#   • OWASP WebGoat payloads
#   • SecLists (danielmiessler/SecLists)
#   • Kaggle: "Web Application Security Dataset"
#   • CSIC HTTP dataset (malicious vs benign requests)

def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_parquet(path)
    # Columns: url, method, headers_json, body, response_code,
    #          response_body, label (0=benign, 1=vulnerable), vuln_type
    return df

# ── 2. FEATURE ENGINEERING ──────────────────────────────────────────────────
def extract_features(df: pd.DataFrame) -> np.ndarray:
    features = pd.DataFrame()

    # URL-level features
    features["url_length"]        = df["url"].str.len()
    features["param_count"]       = df["url"].str.count(r"[?&]")
    features["special_char_ratio"]= df["url"].str.count(r"['\";%<>()]") / features["url_length"]
    features["has_union"]         = df["url"].str.contains("UNION", case=False).astype(int)
    features["has_script_tag"]    = df["url"].str.contains("<script", case=False).astype(int)
    features["has_sleep"]         = df["url"].str.contains("SLEEP|WAITFOR", case=False).astype(int)

    # Request body features
    features["body_length"]       = df["body"].fillna("").str.len()
    features["body_entropy"]      = df["body"].fillna("").apply(_entropy)

    # Response features
    features["resp_code"]         = df["response_code"]
    features["resp_len"]          = df["response_body"].str.len()
    features["error_keyword"]     = df["response_body"].str.contains(
        r"SQL|syntax|mysql|ORA-|Warning.*pg_", case=False).astype(int)
    features["resp_time"]         = df["response_time_ms"]

    # Payload-specific features (for training only)
    features["payload_depth"]     = df["url"].str.count(r"--|\\*/|/\\*")
    features["quote_count"]       = df["url"].str.count(r"['\"]")

    return features.fillna(0).values

def _entropy(s: str) -> float:
    if not s: return 0.0
    from collections import Counter
    import math
    counts = Counter(s)
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

# ── 3. MODEL TRAINING ────────────────────────────────────────────────────────
def train(data_path: str, model_name: str = "sqli_xgb"):
    df = load_dataset(data_path)
    X = extract_features(df)
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    with mlflow.start_run(run_name=model_name):
        # Primary classifier
        clf = XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8,
            scale_pos_weight=len(y[y==0])/len(y[y==1]),  # handle imbalance
            eval_metric="auc", early_stopping_rounds=20,
            random_state=42
        )
        clf.fit(X_train, y_train,
                eval_set=[(X_test, y_test)], verbose=False)

        # Anomaly detector (catches novel attack patterns)
        iso = IsolationForest(n_estimators=200, contamination=0.05,
                              random_state=42)
        iso.fit(X_train[y_train == 0])  # train on benign only

        # Evaluation
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]
        auc = roc_auc_score(y_test, y_prob)

        print(classification_report(y_test, y_pred,
              target_names=["benign", "vulnerable"]))
        print(f"ROC-AUC: {auc:.4f}")

        mlflow.log_metric("roc_auc", auc)
        mlflow.sklearn.log_model(clf, "classifier")
        mlflow.sklearn.log_model(scaler, "scaler")

        joblib.dump(clf, f"models/{model_name}.pkl")
        joblib.dump(scaler, f"models/{model_name}_scaler.pkl")
        joblib.dump(iso, f"models/{model_name}_anomaly.pkl")

    return clf, scaler, iso

# ── 4. INFERENCE ─────────────────────────────────────────────────────────────
class VulnClassifier:
    def __init__(self, model_path: str):
        self.clf = joblib.load(model_path)
        self.scaler = joblib.load(model_path.replace(".pkl", "_scaler.pkl"))
        self.iso = joblib.load(model_path.replace(".pkl", "_anomaly.pkl"))

    def score(self, features: list) -> dict:
        X = self.scaler.transform([features])
        prob = self.clf.predict_proba(X)[0][1]
        anomaly = self.iso.predict(X)[0]   # -1 = anomaly, 1 = normal
        return {
            "confidence": round(float(prob), 4),
            "is_anomaly": anomaly == -1,
            "label": "vulnerable" if prob >= 0.65 else "benign"
        }`;

  return (
    <div>
      <Section title="ML Pipeline Overview">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 0, marginBottom: 24 }}>
          {[
            { step: "01", label: "Data Collection", detail: "NVD, OWASP, SecLists, CSIC HTTP Dataset", color: COLORS.info },
            { step: "02", label: "Feature Engineering", detail: "URL, headers, body, response signals", color: COLORS.accent },
            { step: "03", label: "Model Training", detail: "XGBoost + IsolationForest ensemble", color: COLORS.warn },
            { step: "04", label: "Evaluation", detail: "ROC-AUC, F1, false positive rate", color: COLORS.success },
            { step: "05", label: "Deployment", detail: "MLflow versioning + model registry", color: "#f06292" },
          ].map((s, i) => (
            <div key={i} style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, padding: 16, position: "relative", borderRight: i < 4 ? "none" : `1px solid ${COLORS.border}` }}>
              {i < 4 && <div style={{ position: "absolute", right: -12, top: "50%", transform: "translateY(-50%)", color: COLORS.muted, zIndex: 2, fontSize: 16 }}>→</div>}
              <div style={{ color: s.color, fontSize: 22, fontWeight: 900, opacity: 0.3, marginBottom: 4 }}>{s.step}</div>
              <div style={{ color: COLORS.text, fontWeight: 700, fontSize: 12, marginBottom: 6 }}>{s.label}</div>
              <div style={{ color: COLORS.textDim, fontSize: 11 }}>{s.detail}</div>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Feature Engineering Breakdown" accent={COLORS.info}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 16 }}>
          {[
            { cat: "URL Features", feats: ["URL length", "Parameter count", "Special char ratio", "SQL keyword presence", "Encoding detection", "Path depth"] },
            { cat: "Request Features", feats: ["HTTP method", "Header count", "Content-Type", "Body entropy", "Body length", "Cookie presence"] },
            { cat: "Response Features", feats: ["Status code", "Response size delta", "Error keyword match", "Response time", "Redirect count", "Content type change"] },
          ].map(c => (
            <div key={c.cat} style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 16 }}>
              <div style={{ color: COLORS.accent, fontWeight: 700, fontSize: 12, marginBottom: 10 }}>{c.cat}</div>
              {c.feats.map(f => <div key={f} style={{ color: COLORS.textDim, fontSize: 12, padding: "2px 0" }}>• {f}</div>)}
            </div>
          ))}
        </div>
      </Section>

      <Section title="NLP Report Generator" accent={COLORS.success}>
        <CodeBlock code={`# nlp/report_generator.py
from anthropic import Anthropic
from dataclasses import dataclass
from typing import List

client = Anthropic()

SYSTEM_PROMPT = """You are a senior application security engineer.
Given raw vulnerability scan findings in JSON, produce a structured report with:
1. Executive summary (2-3 sentences, non-technical)
2. Per-finding explanation: what it means, why it matters
3. Concrete remediation steps with code examples
4. Risk rating justification
Output only valid JSON matching the ReportSchema."""

@dataclass
class ReportSection:
    finding_id: str
    plain_english: str      # "This SQL injection allows attackers to..."
    business_impact: str    # "Attackers could exfiltrate your entire user database"
    remediation: str        # Step-by-step fix
    code_example: str       # Patched code snippet
    references: List[str]   # CVE, OWASP links

def generate_report(findings: list) -> dict:
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Generate security report for these findings:\\n{findings}"
        }]
    )
    return response.content[0].text

# Template fallback (no API key required)
REMEDIATION_TEMPLATES = {
    "SQL Injection": {
        "summary": "Untrusted input is directly concatenated into SQL queries.",
        "fix": "Use parameterized queries / prepared statements.",
        "code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "refs": ["CWE-89", "OWASP A03:2021"]
    },
    "Reflected XSS": {
        "summary": "User input echoed back without HTML encoding.",
        "fix": "Escape all output with context-aware encoding.",
        "code": "output = html.escape(user_input, quote=True)",
        "refs": ["CWE-79", "OWASP A03:2021"]
    },
    "CSRF": {
        "summary": "State-changing requests lack anti-forgery tokens.",
        "fix": "Implement CSRF tokens and validate SameSite cookie attribute.",
        "code": "# Django: {% csrf_token %} in forms; Flask-WTF handles automatically",
        "refs": ["CWE-352", "OWASP A01:2021"]
    }
}`} lang="python" />
      </Section>

      <Section title="Full ML Training Code" accent={COLORS.warn}>
        <CodeBlock code={pipelineCode} lang="python" />
      </Section>
    </div>
  );
};