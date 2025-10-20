import React, { useEffect, useState } from 'react';
import { getFindings } from '../api';

function Findings() {
    const [findings, setFindings] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedFinding, setSelectedFinding] = useState(null);
    const [filter, setFilter] = useState('all');

    useEffect(() => {
        loadFindings();
    }, []);

    const loadFindings = async () => {
        try {
            const data = await getFindings();
            setFindings(data);
        } catch (error) {
            console.error('Error loading findings:', error);
        } finally {
            setLoading(false);
        }
    };

    const filteredFindings = findings.filter(f => {
        if (filter === 'all') return true;
        return (f.Severity || '').toLowerCase() === filter;
    });

    if (loading) {
        return <div className="loading">Loading findings...</div>;
    }

    return (
        <div>
            <div className="page-header">
                <h2>Findings</h2>
                <p>Security and compliance findings from evaluations</p>
            </div>

            <div className="card">
                <div style={{ marginBottom: '1rem' }}>
                    <label style={{ marginRight: '1rem', fontWeight: 500 }}>Filter by severity:</label>
                    <select
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #e2e8f0' }}
                    >
                        <option value="all">All</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>

                {filteredFindings.length === 0 ? (
                    <p>No findings match your filter.</p>
                ) : (
                    <table className="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Summary</th>
                                <th>Severity</th>
                                <th>Control ID</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredFindings.map(finding => (
                                <tr key={finding.FindingId}>
                                    <td>{finding.FindingId}</td>
                                    <td>{finding.Summary || 'No summary'}</td>
                                    <td>
                                        <span className={`badge badge-${(finding.Severity || 'low').toLowerCase()}`}>
                                            {finding.Severity || 'Unknown'}
                                        </span>
                                    </td>
                                    <td>{finding.ControlId}</td>
                                    <td>{finding.Status || 'Open'}</td>
                                    <td>
                                        <button
                                            className="btn btn-secondary"
                                            style={{ padding: '0.25rem 0.75rem', fontSize: '0.875rem' }}
                                            onClick={() => setSelectedFinding(finding)}
                                        >
                                            Details
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {selectedFinding && (
                <div className="card" style={{ marginTop: '1.5rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                        <h3>Finding Details</h3>
                        <button className="btn btn-secondary" onClick={() => setSelectedFinding(null)}>Close</button>
                    </div>
                    <div style={{ background: '#f7fafc', padding: '1rem', borderRadius: '6px' }}>
                        <pre style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem' }}>
                            {JSON.stringify(selectedFinding, null, 2)}
                        </pre>
                    </div>
                </div>
            )}
        </div>
    );
}

export default Findings;
