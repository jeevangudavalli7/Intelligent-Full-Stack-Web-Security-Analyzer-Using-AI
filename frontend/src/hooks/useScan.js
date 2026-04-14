import { useState } from 'react';
import { createScan, getScanResults } from '../api/scans';

export const useScan = () => {
  const [scanId, setScanId] = useState(null);
  const [status, setStatus] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState([]);
  const [error, setError] = useState(null);

  const startScan = async (url, mode, intensity, modules) => {
    try {
      setStatus('starting');
      const response = await createScan(url, mode, intensity, modules);
      setScanId(response.scan_id);
      setStatus('queued');
      // In a real app, you'd poll or use WebSocket for updates
    } catch (err) {
      setError(err.message);
      setStatus('error');
    }
  };

  // Additional functions to poll/update...

  return { scanId, status, progress, findings, error, startScan };
};