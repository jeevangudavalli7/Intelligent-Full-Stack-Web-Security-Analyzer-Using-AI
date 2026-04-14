import React from 'react';
import { COLORS } from '../constants/colors';

export const Badge = ({ label, color }) => (
  <span style={{
    background: color + "22",
    color,
    border: `1px solid ${color}55`,
    borderRadius: 4,
    padding: "2px 8px",
    fontSize: 11,
    fontFamily: "monospace",
    fontWeight: 700,
    letterSpacing: 1
  }}>{label}</span>
);