import React, { useEffect, useState } from 'react';
import { getControls, runEvaluation } from '../api';

function Evaluation() {
    const [controls, setControls] = useState([]);
    const [selectedControl, setSelectedControl] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        loadControls();
    }, []);

    const loadControls = async () => {
        try {
            const data = await getControls();
            setControls(data);
        } catch (error) {
            console.error('Error loading controls:', error);
        }
    };

    const handleEvaluate = async () => {
        if (!selectedControl) {
            alert('Please select a control to evaluate');
            return;
        }

        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const data = await runEvaluation(selectedControl);
            setResult(data);
        } catch (err) {
            console.error('Error running evaluation:', err);
            setError(err.response?.data?.detail || 'Failed to run evaluation');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div>
            <div className="page-header">
                <h2>Evaluation</h2>
                <p>Run security and compliance evaluations</p>
            </div>

            <div className="card">
                <h3>Run Evaluation</h3>
                <div className="form-group">
                    <label>Select Control</label>
                    <select
                        value={selectedControl}
                        onChange={(e) => setSelectedControl(e.target.value)}
                        disabled={loading}
                    >
                        <option value="">-- Select a control --</option>
                        {controls.map(control => (
                            <option key={control.ControlId} value={control.ControlId}>
                                {control.ControlId} - {control.Title}
                            </option>
                        ))}
                    </select>
                </div>
                <button
                    className="btn btn-primary"
                    onClick={handleEvaluate}
                    disabled={loading || !selectedControl}
                >
                    {loading ? 'Running...' : 'Run Evaluation'}
                </button>
            </div>

            {error && (
                <div className="error">
                    <strong>Error:</strong> {error}
                </div>
            )}

            {result && (
                <div className="card">
                    <h3>Evaluation Results</h3>
                    <div style={{ marginBottom: '1rem' }}>
                        <p><strong>Control ID:</strong> {result.control_id}</p>
                        <p>
                            <strong>Status:</strong>{' '}
                            <span className={`badge badge-${result.status?.toLowerCase()}`}>
                                {result.status}
                            </span>
                        </p>
                        <p><strong>Message:</strong> {result.message}</p>
                    </div>

                    {result.findings && result.findings.length > 0 && (
                        <div>
                            <h4 style={{ marginBottom: '0.5rem' }}>Findings ({result.findings.length})</h4>
                            <table className="table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Summary</th>
                                        <th>Severity</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {result.findings.map(finding => (
                                        <tr key={finding.FindingId}>
                                            <td>{finding.FindingId}</td>
                                            <td>{finding.Summary}</td>
                                            <td>
                                                <span className={`badge badge-${finding.Severity?.toLowerCase()}`}>
                                                    {finding.Severity}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    <details style={{ marginTop: '1rem' }}>
                        <summary style={{ cursor: 'pointer', fontWeight: 500 }}>View Raw Response</summary>
                        <div style={{ background: '#f7fafc', padding: '1rem', borderRadius: '6px', marginTop: '0.5rem' }}>
                            <pre style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem' }}>
                                {JSON.stringify(result, null, 2)}
                            </pre>
                        </div>
                    </details>
                </div>
            )}
        </div>
    );
}

export default Evaluation;
