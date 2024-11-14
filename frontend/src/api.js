import axios from 'axios';

const API_URL = "http://127.0.0.1:5000";

export const scanForVulnerabilities = async (url, scanType, email) => {
    try {
        const response = await axios.post(`${API_URL}/scan`, { url, scan_type: scanType, email });
        return response.data;
    } catch (error) {
        console.error("Error during scan:", error);
        return { error: "Failed to perform scan" };
    }
};

export const downloadReport = async () => {
    const response = await axios.get(`${API_URL}/download_report`, {
        responseType: 'blob',
    });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'scan_report.txt');
    document.body.appendChild(link);
    link.click();
};
