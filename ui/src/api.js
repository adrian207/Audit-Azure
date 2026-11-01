import axios from 'axios';

// All API calls go through the dashboard's own server at /api, which forwards them
// to the API and adds the X-API-Key header (see vite.config.js). The key never
// reaches the browser.
const API_BASE = '/api';

const api = axios.create({
    baseURL: API_BASE,
    headers: {
        'Content-Type': 'application/json'
    }
});

export const getEvidence = async () => {
    const response = await api.get('/evidence');
    return response.data;
};

export const getFindings = async () => {
    const response = await api.get('/findings');
    return response.data;
};

export const getControls = async () => {
    const response = await api.get('/controls');
    return response.data;
};

export const runEvaluation = async (controlId) => {
    const response = await api.post('/run-evaluation', { control_id: controlId });
    return response.data;
};

export const createEvidence = async (evidence) => {
    const response = await api.post('/evidence', evidence);
    return response.data;
};

export default api;
