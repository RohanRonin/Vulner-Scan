import React, { useState } from 'react';
import { scanForVulnerabilities, downloadReport } from './api';
import './Scanner.css';

const Scanner = () => {
    const [url, setUrl] = useState('');
    const [scanType, setScanType] = useState('sql_injection');
    const [email, setEmail] = useState('');
    const [result, setResult] = useState(null);

    const handleScan = async () => {
        const data = await scanForVulnerabilities(url, scanType, email);
        setResult(data);
    };

    const handleDownloadReport = async () => {
        await downloadReport();
    };

    return (
        <div className="scanner-container">
            <h2 className="scanner-title">Vulnerability Scanner</h2>
            <div className="scanner-form">
                <div className="scanner-input-group">
                    <label>Target URL:</label>
                    <input
                        type="text"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        placeholder="Enter URL"
                        className="scanner-input"
                    />
                </div>

                <div className="scanner-input-group">
                    <label>Scan Type:</label>
                    <select
                        value={scanType}
                        onChange={(e) => setScanType(e.target.value)}
                        className="scanner-select"
                    >
                        <option value="sql_injection">SQL Injection</option>
                        <option value="command_injection">Command Injection</option>
                        <option value="xss">XSS</option>
                    </select>
                </div>

                <div className="scanner-input-group">
                    <label>Email (optional for report):</label>
                    <input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="Enter email for report"
                        className="scanner-input"
                    />
                </div>

                <button onClick={handleScan} className="scanner-button">
                    Start Scan
                </button>
            </div>

            {result && (
                <div className="scanner-result">
                    {result.error ? (
                        <p className="error">Error: {result.error}</p>
                    ) : (
                        <div>
                            <p>Vulnerability Status: {result.vulnerable ? "Vulnerable" : "Not Vulnerable"}</p>
                            {result.vulnerable && (
                                <div>
                                    <p><strong>Payload:</strong> {result.payload}</p>
                                    <p><strong>Scan Type:</strong> {result.scan_type}</p>
                                    <p><strong>Date & Time:</strong> {result.timestamp}</p>
                                </div>
                            )}
                            <button onClick={handleDownloadReport} className="download-button">
                                Download Report
                            </button>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default Scanner;
