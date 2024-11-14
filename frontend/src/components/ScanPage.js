import React, { useState } from 'react';

const ScanPage = () => {
  const [url, setUrl] = useState('');
  const [scanId, setScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState('idle');
  const [alerts, setAlerts] = useState([]);

  const handleStartScan = async () => {
    const response = await fetch('/scan/start_scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await response.json();
    setScanId(data.scan_id);
    setScanStatus('in_progress');
    checkScanStatus(data.scan_id);
  };

  const checkScanStatus = async (scanId) => {
    const intervalId = setInterval(async () => {
      const response = await fetch(`/scan/scan_results/${scanId}`);
      const data = await response.json();
      if (data.status === 'completed') {
        clearInterval(intervalId);
        setAlerts(data.alerts);
        setScanStatus('completed');
      }
    }, 5000);
  };

  return (
    <div>
      <h2>Web Vulnerability Scanner</h2>
      <input type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Enter URL" required />
      <button onClick={handleStartScan}>Start Scan</button>

      {scanStatus === 'in_progress' && <p>Scanning in progress...</p>}
      {scanStatus === 'completed' && (
        <div>
          <h3>Scan Results:</h3>
          <ul>
            {alerts.map((alert, index) => (
              <li key={index}>{alert.alert}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default ScanPage;
