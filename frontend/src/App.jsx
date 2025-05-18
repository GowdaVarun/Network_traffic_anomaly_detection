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

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend, ArcElement);

const API_GET_DATA = "http://localhost:8080/get-data";

const App = () => {
    const [data, setData] = useState(null);

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

    const toIP = (num) => {
        return [24, 16, 8, 0].map(shift => (num >> shift) & 255).join('.');
    };

    const topIPs = (ipArray) => ipArray.slice(0, 10).map(toIP);

    const renderPerformanceChart = () => {
        const metrics = data?.model_performance || {};
        return (
            <div className="chart-block">
                <h3>Model Performance</h3>
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
                <h3>Protocol Distribution</h3>
                <Pie
                    data={{
                        labels: Object.keys(protocols),
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
        const mapping = { '1': 'Port Scanning', '2': 'DOS', '3': 'Brute Force', '4': 'DNS Tunneling' };
        const types = data?.anomaly_summary?.anomalies_by_type || {};
        return (
            <div className="chart-block">
                <h3>Anomalies by Type</h3>
                <Bar
                    data={{
                        labels: Object.keys(types).map(k => mapping[k] || 'Other'),
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
                    <h4>Top Source IPs</h4>
                    <ul>{srcIPs.map((ip, idx) => <li key={idx}>{ip}</li>)}</ul>
                </div>
                <div>
                    <h4>Top Destination IPs</h4>
                    <ul>{dstIPs.map((ip, idx) => <li key={idx}>{ip}</li>)}</ul>
                </div>
            </div>
        );
    };

    if (!data) return <p>Loading network data...</p>;

    const summary = data.anomaly_summary;
    const anomalyPct = summary.anomaly_percentage.toFixed(2);

    return (
        <div className="App">
            <header>
                <h1>Network Traffic Anomaly Dashboard</h1>
                <p>Last Analysis: {data.analysis_timestamp}</p>
            </header>

            <section className="metrics">
                <div className="card">
                    <h3>Total Packets</h3>
                    <p>{summary.total_packets}</p>
                </div>
                <div className="card">
                    <h3>Total Anomalies</h3>
                    <p>{summary.total_anomalies}</p>
                </div>
                <div className="card">
                    <h3>Anomaly %</h3>
                    <p>{anomalyPct} %</p>
                </div>
                <div className="card">
                    <h3>Last Anomaly</h3>
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
                <p>Network Anomaly Detection System © 2025</p>
            </footer>
        </div>
    );
};

export default App;