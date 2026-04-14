import React from 'react';
import { COLORS } from '../constants/colors';

export const InfoCard = ({ icon, title, items, accent }) => (
  <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 20 }}>
    <div style={{ fontSize: 20, marginBottom: 8 }}>{icon}</div>
    <div style={{ color: accent || COLORS.accent, fontWeight: 700, fontSize: 13, marginBottom: 12, letterSpacing: 0.5 }}>{title}</div>
    {items.map((item, i) => (
      <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8, marginBottom: 8 }}>
        <span style={{ color: accent || COLORS.accent, marginTop: 2, fontSize: 10 }}>▸</span>
        <span style={{ color: COLORS.textDim, fontSize: 13, lineHeight: 1.5 }}>{item}</span>
      </div>
    ))}
  </div>
);