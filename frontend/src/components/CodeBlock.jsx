// frontend/src/components/CodeBlock.jsx  — REPLACE your existing file (currently named codeblock.jsx)
import React, { useState } from 'react';

export const CodeBlock = ({ code, lang = "python" }) => {
  const [copied, setCopied] = useState(false);
  const pyKws  = ["def ","class ","import ","from ","return ","if ","else:","elif ","for ","in ","try:","except ","with ","async ","await ","True","False","None","yield","lambda ","pass","raise "];
  const jsKws  = ["const ","let ","var ","function ","return ","if ","else ","for ","async ","await ","import ","export ","class ","new "];
  const kws    = lang === "python" ? pyKws : jsKws;

  const highlight = (line) => {
    if (line.trim().startsWith("#") || line.trim().startsWith("//"))
      return <span style={{ color: "var(--text-muted)" }}>{line}</span>;
    if (line.includes('"""') || (line.trim().startsWith('"') && line.trim().endsWith('"')))
      return <span style={{ color: "#a5d6a7" }}>{line}</span>;
    const strMatch = line.match(/(["'`])(.*?)\1/);
    if (strMatch) {
      const before = line.slice(0, strMatch.index);
      const after  = line.slice(strMatch.index + strMatch[0].length);
      return <span><span>{before}</span><span style={{ color: "#a5d6a7" }}>{strMatch[0]}</span><span>{after}</span></span>;
    }
    for (const kw of kws) {
      if (line.includes(kw))
        return <span><span style={{ color: "var(--info)" }}>{kw}</span><span>{line.replace(kw, "")}</span></span>;
    }
    return <span>{line}</span>;
  };

  return (
    <div style={{ position: "relative", background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, overflow: "hidden", marginTop: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 16px", background: "var(--card)", borderBottom: "1px solid var(--border)" }}>
        <span style={{ color: "var(--text-muted)", fontSize: 11, fontFamily: "monospace", letterSpacing: 1 }}>{lang}</span>
        <button
          onClick={() => { navigator.clipboard?.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
          style={{ background: "none", border: "1px solid var(--border)", color: copied ? "var(--success)" : "var(--text-muted)", borderRadius: 4, padding: "2px 10px", fontSize: 11, cursor: "pointer" }}>
          {copied ? "✓ copied" : "copy"}
        </button>
      </div>
      <pre style={{ margin: 0, padding: "16px", overflowX: "auto", fontSize: 12.5, lineHeight: 1.7, fontFamily: "'JetBrains Mono', 'Fira Code', monospace", color: "var(--text)" }}>
        {code.split("\n").map((line, i) => (
          <div key={i} style={{ display: "flex" }}>
            <span style={{ color: "var(--text-muted)", minWidth: 28, userSelect: "none", fontSize: 11 }}>{i + 1}</span>
            <span>{highlight(line)}</span>
          </div>
        ))}
      </pre>
    </div>
  );
};