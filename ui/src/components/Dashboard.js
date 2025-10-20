import React, { useEffect, useState } from 'react';
import { getEvidence, getFindings, getControls } from '../api';

function Dashboard() {
    const [stats, setStats] = useState({
        evidenceCount: 0,
        findingsCount: 0,
        controlsCount: 0,
        highSeverityCount: 0
    });
    const [recentFindings, setRecentFindings] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadDashboard();
    }, []);

    const loadDashboard = async () => {
        try {
            const [evidence, findings, controls] = await Promise.all([
                getEvidence(),
                getFindings(),
                getControls()
            ]);

            const highSeverity = findings.filter(f =>
                f.Severity?.toLowerCase() === 'high' || f.Severity?.toLowerCase() === 'critical'
            ).length;

            setStats({
                evidenceCount: evidence.length,
                findingsCount: findings.length,
                controlsCount: controls.length,
                highSeverityCount: highSeverity
            });

            setRecentFindings(findings.slice(0, 5));
        } catch (error) {
            console.error('Error loading dashboard:', error);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return <div className="loading">Loading dashboard...</div>;
    }

    return (
        <div>
            <div className="page-header">
                <h2>Dashboard</h2>
                <p>Overview of your Azure audit status</p>
            </div>

            <div className="stats-grid">
                <div className="stat-card">
                    <h3>Evidence Items</h3>
                    <div className="stat-value">{stats.evidenceCount}</div>
                </div>
                <div className="stat-card">
                    <h3>Total Findings</h3>
                    <div className="stat-value">{stats.findingsCount}</div>
                </div>
                <div className="stat-card">
                    <h3>High Severity</h3>
                    <div className="stat-value">{stats.highSeverityCount}</div>
                </div>
                <div className="stat-card">
                    <h3>Controls</h3>
                    <div className="stat-value">{stats.controlsCount}</div>
                </div>
            </div>

            <div className="card">
                <h3>Recent Findings</h3>
                {recentFindings.length === 0 ? (
                    <p>No findings yet. Run an evaluation to get started.</p>
                ) : (
                    <table className="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Summary</th>
                                <th>Severity</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {recentFindings.map(finding => (
                                <tr key={finding.FindingId}>
                                    <td>{finding.FindingId}</td>
                                    <td>{finding.Summary || 'No summary'}</td>
                                    <td>
                                        <span className={`badge badge-${(finding.Severity || 'low').toLowerCase()}`}>
                                            {finding.Severity || 'Unknown'}
                                        </span>
                                    </td>
                                    <td>{finding.Status || 'Open'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}

export default Dashboard;
