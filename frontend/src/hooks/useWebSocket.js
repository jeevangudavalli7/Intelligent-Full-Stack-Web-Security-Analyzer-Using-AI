import { useEffect, useRef, useState } from 'react';

export const useWebSocket = (scanId, onMessage) => {
  const [connected, setConnected] = useState(false);
  const ws = useRef(null);

  useEffect(() => {
    if (!scanId) return;
    ws.current = new WebSocket(`ws://localhost:8001/ws/scans/${scanId}`);
    ws.current.onopen = () => setConnected(true);
    ws.current.onmessage = (event) => onMessage(JSON.parse(event.data));
    ws.current.onclose = () => setConnected(false);
    return () => ws.current?.close();
  }, [scanId, onMessage]);

  return connected;
};