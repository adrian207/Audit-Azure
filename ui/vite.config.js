import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
    // Server-side settings: the repository-root .env (written by install.sh), then real
    // environment variables (docker-compose). Only VITE_* variables reach the browser,
    // so API_MASTER_KEY stays on the server.
    const env = { ...loadEnv(mode, '..', ''), ...process.env };
    const target = env.API_PROXY_TARGET || 'http://localhost:8000';
    const apiKey = env.API_MASTER_KEY || '';

    const apiProxy = {
        '/api': {
            target,
            changeOrigin: true,
            rewrite: (path) => path.replace(/^\/api/, ''),
            headers: apiKey ? { 'X-API-Key': apiKey } : {}
        }
    };

    return {
        plugins: [react()],
        server: {
            host: true,
            port: 3000,
            strictPort: true,
            proxy: apiProxy
        },
        preview: {
            port: 3000,
            proxy: apiProxy
        },
        build: {
            outDir: 'build'
        }
    };
});
