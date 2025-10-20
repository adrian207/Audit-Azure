import React, { useEffect, useState } from 'react';
import { getControls } from '../api';

function Controls() {
    const [controls, setControls] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadControls();
    }, []);

    const loadControls = async () => {
        try {
            const data = await getControls();
            setControls(data);
        } catch (error) {
            console.error('Error loading controls:', error);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return <div className="loading">Loading controls...</div>;
    }

    return (
        <div>
            <div className="page-header">
                <h2>Controls</h2>
                <p>Security and compliance control catalog</p>
            </div>

            <div className="card">
                <h3>Control Catalog ({controls.length})</h3>
                {controls.length === 0 ? (
                    <p>No controls defined yet.</p>
                ) : (
                    <table className="table">
                        <thead>
                            <tr>
                                <th>Control ID</th>
                                <th>Title</th>
                                <th>Domain</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {controls.map(control => (
                                <tr key={control.ControlId}>
                                    <td><strong>{control.ControlId}</strong></td>
                                    <td>{control.Title}</td>
                                    <td>
                                        <span className="badge" style={{ background: '#e6fffa', color: '#234e52' }}>
                                            {control.Domain}
                                        </span>
                                    </td>
                                    <td>{control.Description}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}

export default Controls;
