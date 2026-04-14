const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export const createScan = async (targetUrl, mode, intensity, modules) => {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ target_url: targetUrl, mode, intensity, modules }),
  });
  if (!res.ok) throw new Error('Failed to start scan');
  return res.json();
};

export const getScan = async (scanId) => {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/scans/${scanId}`, {
    headers: { 'Authorization': `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch scan');
  return res.json();
};

export const getReport = async (scanId) => {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/scans/${scanId}/report`, {
    headers: { 'Authorization': `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch report');
  return res.json();
};