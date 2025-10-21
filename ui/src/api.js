import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

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
