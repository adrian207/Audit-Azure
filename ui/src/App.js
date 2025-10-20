import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Evidence from './components/Evidence';
import Findings from './components/Findings';
import Controls from './components/Controls';
import Evaluation from './components/Evaluation';
import './App.css';

function App() {
    return (
        <Router>
            <div className="app">
                <nav className="navbar">
                    <div className="nav-brand">
                        <h1>🛡️ Audit-Azure</h1>
                        <p className="nav-subtitle">Azure Security & Compliance Platform</p>
                    </div>
                    <ul className="nav-links">
                        <li><Link to="/">Dashboard</Link></li>
                        <li><Link to="/evidence">Evidence</Link></li>
                        <li><Link to="/findings">Findings</Link></li>
                        <li><Link to="/controls">Controls</Link></li>
                        <li><Link to="/evaluation">Evaluation</Link></li>
                    </ul>
                </nav>
                <main className="main-content">
                    <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/evidence" element={<Evidence />} />
                        <Route path="/findings" element={<Findings />} />
                        <Route path="/controls" element={<Controls />} />
                        <Route path="/evaluation" element={<Evaluation />} />
                    </Routes>
                </main>
            </div>
        </Router>
    );
}

export default App;

