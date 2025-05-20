import React, { useEffect, useState } from 'react';
import './App.css';
import { Bar, Pie } from 'react-chartjs-2';
import {
    Chart as ChartJS,
    BarElement,
    CategoryScale,
    LinearScale,
    Tooltip,
    Legend,
    ArcElement
} from 'chart.js';
import ParticleComponent from './particle';

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend, ArcElement);

const API_GET_DATA = "http://localhost:8080/get-data";

// Language translations
const translations = {
    en: {
        networkDashboard: "Network Traffic Anomaly Dashboard",
        lastAnalysis: "Last Analysis",
        totalPackets: "Total Packets",
        totalAnomalies: "Total Anomalies",
        anomalyPercent: "Anomaly %",
        lastAnomaly: "Last Anomaly",
        modelPerformance: "Model Performance",
        protocolDistribution: "Protocol Distribution",
        anomaliesByType: "Anomalies by Type",
        topSourceIPs: "Top Source IPs",
        topDestinationIPs: "Top Destination IPs",
        loading: "Loading network data...",
        copyright: "Network Anomaly Detection System © 2025",
        anomalyMapping: {
            '1': 'Port Scanning',
            '2': 'DOS',
            '3': 'Brute Force',
            '4': 'DNS Tunneling'
        },
        selectLanguage: "Language"
    },
    kn: {
        networkDashboard: "ಜಾಲ ಸಂಚಾರ ಅಸಾಮಾನ್ಯತೆ ಡ್ಯಾಶ್‌ಬೋರ್ಡ್",
        lastAnalysis: "ಕೊನೆಯ ವಿಶ್ಲೇಷಣೆ",
        totalPackets: "ಒಟ್ಟು ಪ್ಯಾಕೆಟ್‌ಗಳು",
        totalAnomalies: "ಒಟ್ಟು ಅಸಾಮಾನ್ಯತೆಗಳು",
        anomalyPercent: "ಅಸಾಮಾನ್ಯತೆ %",
        lastAnomaly: "ಕೊನೆಯ ಅಸಾಮಾನ್ಯತೆ",
        modelPerformance: "ಮಾದರಿ ಕಾರ್ಯಕ್ಷಮತೆ",
        protocolDistribution: "ಪ್ರೋಟೋಕಾಲ್ ಹಂಚಿಕೆ",
        anomaliesByType: "ಪ್ರಕಾರದಿಂದ ಅಸಾಮಾನ್ಯತೆಗಳು",
        topSourceIPs: "ಪ್ರಮುಖ ಮೂಲ IPಗಳು",
        topDestinationIPs: "ಪ್ರಮುಖ ಗಮ್ಯಸ್ಥಾನ IPಗಳು",
        loading: "ಜಾಲ ಡೇಟಾವನ್ನು ಲೋಡ್ ಮಾಡಲಾಗುತ್ತಿದೆ...",
        copyright: "ಜಾಲ ಅಸಾಮಾನ್ಯತೆ ಪತ್ತೆ ವ್ಯವಸ್ಥೆ © 2025",
        anomalyMapping: {
            '1': 'ಪೋರ್ಟ್ ಸ್ಕ್ಯಾನಿಂಗ್',
            '2': 'DOS ದಾಳಿ',
            '3': 'ಬ್ರೂಟ್ ಫೋರ್ಸ್',
            '4': 'DNS ಟನಲಿಂಗ್'
        },
        selectLanguage: "ಭಾಷೆ"
    },
    hi: {
        networkDashboard: "नेटवर्क ट्रैफिक विसंगति डैशबोर्ड",
        lastAnalysis: "अंतिम विश्लेषण",
        totalPackets: "कुल पैकेट्स",
        totalAnomalies: "कुल विसंगतियाँ",
        anomalyPercent: "विसंगति %",
        lastAnomaly: "अंतिम विसंगति",
        modelPerformance: "मॉडल प्रदर्शन",
        protocolDistribution: "प्रोटोकॉल वितरण",
        anomaliesByType: "प्रकार अनुसार विसंगतियाँ",
        topSourceIPs: "शीर्ष स्रोत IPs",
        topDestinationIPs: "शीर्ष गंतव्य IPs",
        loading: "नेटवर्क डेटा लोड हो रहा है...",
        copyright: "नेटवर्क विसंगति डिटेक्शन सिस्टम © 2025",
        anomalyMapping: {
            '1': 'पोर्ट स्कैनिंग',
            '2': 'DOS हमला',
            '3': 'ब्रूट फोर्स',
            '4': 'DNS टनलिंग'
        },
        selectLanguage: "भाषा"
    }
};

const LANGUAGES = [
    { code: 'en', label: 'English' },
    { code: 'kn', label: 'ಕನ್ನಡ' },
    { code: 'hi', label: 'हिन्दी' }
];

const App = () => {
    const [data, setData] = useState(null);
    const [lang, setLang] = useState('en');

    useEffect(() => {
        const fetchData = async () => {
            const res = await fetch(API_GET_DATA);
            const json = await res.json();
            setData(json);
        };

        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, []);

    const t = translations[lang];

    const toIP = (num) => {
        return [24, 16, 8, 0].map(shift => (num >> shift) & 255).join('.');
    };

    const topIPs = (ipArray) => (ipArray || []).slice(0, 10).map(toIP);

    const renderPerformanceChart = () => {
        const metrics = data?.model_performance || {};
        return (
            <div className="chart-block">
                <h3>{t.modelPerformance}</h3>
                <Bar
                    data={{
                        labels: Object.keys(metrics),
                        datasets: [{
                            label: 'Score',
                            data: Object.values(metrics),
                            backgroundColor: '#4bc0c0'
                        }]
                    }}
                    options={{ scales: { y: { min: 0, max: 1 } } }}
                />
            </div>
        );
    };

    const renderProtocolChart = () => {
        const protocols = data?.anomaly_summary?.protocol_distribution || {};
        return (
            <div className="chart-block">
            <h3>{t.protocolDistribution}</h3>
            <Pie
                data={{
                labels: Object.keys(protocols).map(k => k === '0' ? 'TCP' : k === '1' ? 'UDP' : k),
                datasets: [{
                    label: 'Protocol Count',
                    data: Object.values(protocols),
                    backgroundColor: ['#36a2eb', '#ff6384', '#ffcd56', '#9966ff']
                }]
                }}
            />
            </div>
        );
    };

    const renderAnomalyTypeChart = () => {
        const types = data?.anomaly_summary?.anomalies_by_type || {};
        return (
            <div className="chart-block">
                <h3>{t.anomaliesByType}</h3>
                <Bar
                    data={{
                        labels: Object.keys(types).map(k => t.anomalyMapping[k] || 'Other'),
                        datasets: [{
                            label: 'Anomaly Count',
                            data: Object.values(types),
                            backgroundColor: '#ff6384'
                        }]
                    }}
                />
            </div>
        );
    };

    const renderTopIPs = () => {
        const srcIPs = topIPs(data?.anomaly_summary?.source_ips || []);
        const dstIPs = topIPs(data?.anomaly_summary?.destination_ips || []);

        return (
            <div className="ip-lists">
                <div>
                    <h4>{t.topSourceIPs}</h4>
                    <ul>{srcIPs.map((ip, idx) => <li key={idx}>{ip}</li>)}</ul>
                </div>
                <div>
                    <h4>{t.topDestinationIPs}</h4>
                    <ul>{dstIPs.map((ip, idx) => <li key={idx}>{ip}</li>)}</ul>
                </div>
            </div>
        );
    };

    if (!data) return <p>{t.loading}</p>;

    const summary = data.anomaly_summary;
    const anomalyPct = summary.anomaly_percentage.toFixed(2);

    return (
        <div className="App">
            <header>
            <ParticleComponent />
                <h1>{t.networkDashboard}</h1>
                <div className="lang-switcher">
                    <label htmlFor="language-select">{t.selectLanguage}:</label>
                    <select
                        id="language-select"
                        value={lang}
                        onChange={e => setLang(e.target.value)}
                    >
                        {LANGUAGES.map(l => (
                            <option key={l.code} value={l.code}>{l.label}</option>
                        ))}
                    </select>
                </div>
                <p>{t.lastAnalysis}: {data.analysis_timestamp}</p>
            </header>

            <section className="metrics">
                <div className="card">
                    <h3>{t.totalPackets}</h3>
                    <p>{summary.total_packets}</p>
                </div>
                <div className="card">
                    <h3>{t.totalAnomalies}</h3>
                    <p>{summary.total_anomalies}</p>
                </div>
                <div className="card">
                    <h3>{t.anomalyPercent}</h3>
                    <p>{anomalyPct} %</p>
                </div>
                <div className="card">
                    <h3>{t.lastAnomaly}</h3>
                    <p>{summary.last_anomaly_seen}</p>
                </div>
            </section>

            <section className="charts">
                {renderPerformanceChart()}
                {renderProtocolChart()}
                {renderAnomalyTypeChart()}
            </section>

            <section className="ip-section">
                {renderTopIPs()}
            </section>

            <footer>
                <p>{t.copyright}</p>
            </footer>
        </div>
    );
};

export default App;