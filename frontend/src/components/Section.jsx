import React from 'react';
import { COLORS } from '../constants/colors';

export const Section = ({ title, children, accent }) => (
  <div style={{ marginBottom: 32 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
      <div style={{ width: 4, height: 20, background: accent || COLORS.accent, borderRadius: 2 }} />
      <h3 style={{ color: COLORS.text, fontSize: 16, fontWeight: 700, margin: 0, letterSpacing: 0.5 }}>{title}</h3>
    </div>
    {children}
  </div>
);