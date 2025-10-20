import React, { useEffect, useState } from 'react';
import { getEvidence, createEvidence } from '../api';

function Evidence() {
    const [evidence, setEvidence] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showForm, setShowForm] = useState(false);
    const [formData, setFormData] = useState({
        ResourceId: '',
        ResourceType: '',
        Region: '',
        Data: ''
    });

    useEffect(() => {
        loadEvidence();
    }, []);

    const loadEvidence = async () => {
        try {
            const data = await getEvidence();
            setEvidence(data);
        } catch (error) {
            console.error('Error loading evidence:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const evidenceData = {
                ...formData,
                Data: JSON.parse(formData.Data || '{}')
            };
            await createEvidence(evidenceData);
            setShowForm(false);
            setFormData({ ResourceId: '', ResourceType: '', Region: '', Data: '' });
            loadEvidence();
        } catch (error) {
            console.error('Error creating evidence:', error);
            alert('Error creating evidence. Please check the data format.');
        }
    };

    if (loading) {
        return <div className="loading">Loading evidence...</div>;
    }

    return (
        <div>
            <div className="page-header">
                <h2>Evidence</h2>
                <p>Azure resource evidence collection</p>
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
                            <label>Resource ID</label>
                            <input
                                type="text"
                                value={formData.ResourceId}
                                onChange={(e) => setFormData({ ...formData, ResourceId: e.target.value })}
                                required
                            />
                        </div>
                        <div className="form-group">
                            <label>Resource Type</label>
                            <input
                                type="text"
                                value={formData.ResourceType}
                                onChange={(e) => setFormData({ ...formData, ResourceType: e.target.value })}
                                required
                            />
                        </div>
                        <div className="form-group">
                            <label>Region</label>
                            <input
                                type="text"
                                value={formData.Region}
                                onChange={(e) => setFormData({ ...formData, Region: e.target.value })}
                            />
                        </div>
                        <div className="form-group">
                            <label>Data (JSON format)</label>
                            <textarea
                                rows="4"
                                value={formData.Data}
                                onChange={(e) => setFormData({ ...formData, Data: e.target.value })}
                                placeholder='{"key": "value"}'
                            />
                        </div>
                        <button type="submit" className="btn btn-primary">Create Evidence</button>
                    </form>
                </div>
            )}

            <div className="card">
                <h3>Evidence Items ({evidence.length})</h3>
                {evidence.length === 0 ? (
                    <p>No evidence collected yet.</p>
                ) : (
                    <table className="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Resource ID</th>
                                <th>Type</th>
                                <th>Region</th>
                                <th>Collected</th>
                            </tr>
                        </thead>
                        <tbody>
                            {evidence.map(item => (
                                <tr key={item.EvidenceId}>
                                    <td>{item.EvidenceId}</td>
                                    <td>{item.ResourceId}</td>
                                    <td>{item.ResourceType}</td>
                                    <td>{item.Region || 'N/A'}</td>
                                    <td>{new Date(item.CollectedAt).toLocaleString()}</td>
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
