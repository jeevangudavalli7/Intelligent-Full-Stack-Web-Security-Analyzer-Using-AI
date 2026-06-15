// frontend/src/api/scans.js  — REPLACE your existing file entirely with this
// (Your current file is a copy of auth.js — this is the correct version)

const BASE = '/api/v1';

export const createScan = async (targetUrl, mode, intensity, modules, token) => {
  const res = await fetch(`${BASE}/scans/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ target_url: targetUrl, mode, intensity, modules }),
  });
  if (!res.ok) { const e = await res.json(); throw new Error(e.detail || 'Failed to create scan'); }
  return res.json();
};

export const getScanStatus = async (scanId, token) => {
  const res = await fetch(`${BASE}/scans/${scanId}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) { const e = await res.json(); throw new Error(e.detail || 'Failed to get scan'); }
  return res.json();
};

export const listScans = async (token) => {
  const res = await fetch(`${BASE}/scans/`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) { const e = await res.json(); throw new Error(e.detail || 'Failed to list scans'); }
  return res.json();
};

export const deleteScan = async (scanId, token) => {
  const res = await fetch(`${BASE}/scans/${scanId}`, {
    method: 'DELETE',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) { const e = await res.json(); throw new Error(e.detail || 'Failed to delete scan'); }
  return res.json();
};