import React, { useEffect, useState } from 'react';

function App() {
    const [findings, setFindings] = useState([]);

    useEffect(() => {
        fetch('/findings')
            .then(r => r.json())
            .then(data => setFindings(data || []))
            .catch(err => console.error(err));
    }, []);

    function showDetails(f) {
        setSelected(f);
    }

    function previewRemediation(findingId) {
        fetch('/remediation/preview', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ findingId }) })
            .then(r => r.json())
            .then(d => alert('Preview: ' + JSON.stringify(d)))
            .catch(e => alert('Preview failed'))
    }

    function executeRemediation(findingId) {
        fetch('/remediation/execute', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ findingId, approve: true }) })
            .then(r => r.json())
            .then(d => alert('Execute: ' + JSON.stringify(d)))
            .catch(e => alert('Execute failed'))
    }

    return (
        <div style={{ padding: 20 }}>
            <h1>Azure Audit — Findings</h1>
            {findings.length === 0 ? (
                <p>No findings yet.</p>
            ) : (
                <ul>
                    {findings.map(f => (
                        <li key={f.FindingId}>
                            <strong>{f.Summary}</strong> — {f.Severity}
                            <div>
                                <button onClick={() => showDetails(f)}>Details</button>
                                <button onClick={() => previewRemediation(f.FindingId)}>Preview Fix</button>
                                <button onClick={() => executeRemediation(f.FindingId)}>Execute Fix</button>
                            </div>
                        </li>
                    ))}
                </ul>
            )}

            {selected && (
                <div style={{ marginTop: 20, padding: 10, border: '1px solid #ccc' }}>
                    <h3>Details</h3>
                    <pre>{JSON.stringify(selected, null, 2)}</pre>
                </div>
            )}
        </div>
    );
}

export default App;
