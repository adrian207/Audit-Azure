import React, { useEffect, useState } from 'react';
import { getEvidence, createEvidence } from '../api';

const EMPTY_FORM = { Source: '', QueryOrRequest: '', RawResult: '' };

function Evidence() {
    const [evidence, setEvidence] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [showForm, setShowForm] = useState(false);
    const [formData, setFormData] = useState(EMPTY_FORM);

    useEffect(() => {
        loadEvidence();
    }, []);

    const loadEvidence = async () => {
        try {
            setError('');
            const data = await getEvidence();
            setEvidence(data);
        } catch (err) {
            console.error('Error loading evidence:', err);
            setError('Could not load evidence from the API.');
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        const raw = formData.RawResult.trim();
        if (raw) {
            try {
                JSON.parse(raw);
            } catch {
                alert('Raw result must be valid JSON.');
                return;
            }
        }
        try {
            await createEvidence({
                Source: formData.Source,
                QueryOrRequest: formData.QueryOrRequest,
                RawResult: raw || null
            });
            setShowForm(false);
            setFormData(EMPTY_FORM);
            loadEvidence();
        } catch (err) {
            console.error('Error creating evidence:', err);
            alert('Error creating evidence. Check the API is running and try again.');
        }
    };

    if (loading) {
        return <div className="loading">Loading evidence...</div>;
    }

    return (
        <div>
            <div className="page-header">
                <h2>Evidence</h2>
                <p>Raw results collected from Azure, used by evaluators</p>
            </div>

            <div style={{ marginBottom: '1.5rem' }}>
                <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
                    {showForm ? 'Cancel' : '+ Add Evidence'}
                </button>
            </div>

            {showForm && (
                <div className="card">
                    <h3>New Evidence</h3>
                    <form onSubmit={handleSubmit}>
                        <div className="form-group">
                            <label>Source</label>
                            <input
                                type="text"
                                value={formData.Source}
                                onChange={(e) => setFormData({ ...formData, Source: e.target.value })}
                                placeholder="e.g. Resource Graph, Microsoft Graph, Defender"
                                required
                            />
                        </div>
                        <div className="form-group">
                            <label>Query or request</label>
                            <input
                                type="text"
                                value={formData.QueryOrRequest}
                                onChange={(e) => setFormData({ ...formData, QueryOrRequest: e.target.value })}
                                placeholder="The query or API call that produced the result"
                                required
                            />
                        </div>
                        <div className="form-group">
                            <label>Raw result (JSON)</label>
                            <textarea
                                rows="6"
                                value={formData.RawResult}
                                onChange={(e) => setFormData({ ...formData, RawResult: e.target.value })}
                                placeholder='{"users": [{"id": "user-1", "mfaEnabled": false}]}'
                            />
                        </div>
                        <button type="submit" className="btn btn-primary">Create Evidence</button>
                    </form>
                </div>
            )}

            <div className="card">
                <h3>Evidence Items ({evidence.length})</h3>
                {error ? (
                    <p>{error}</p>
                ) : evidence.length === 0 ? (
                    <p>No evidence collected yet.</p>
                ) : (
                    <table className="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Source</th>
                                <th>Query or request</th>
                                <th>Collected</th>
                                <th>SHA-256</th>
                            </tr>
                        </thead>
                        <tbody>
                            {evidence.map(item => (
                                <tr key={item.EvidenceId}>
                                    <td>{item.EvidenceId}</td>
                                    <td>{item.Source}</td>
                                    <td>{item.QueryOrRequest}</td>
                                    <td>{item.Timestamp ? new Date(item.Timestamp).toLocaleString() : 'N/A'}</td>
                                    <td title={item.Hash}>{item.Hash ? `${item.Hash.slice(0, 12)}…` : 'N/A'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}

export default Evidence;
