import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
    plugins: [react()],
    // Keep REACT_APP_* variables (docker-compose sets REACT_APP_API_URL) working alongside VITE_*
    envPrefix: ['VITE_', 'REACT_APP_'],
    server: {
        host: true,
        port: 3000,
        strictPort: true
    },
    preview: {
        port: 3000
    },
    build: {
        outDir: 'build'
    }
});
