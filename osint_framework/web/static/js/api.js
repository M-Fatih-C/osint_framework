const API_BASE = '/api/v1';

async function parseApiError(res) {
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        try {
            const payload = await res.json();
            const detail = payload?.detail;
            if (Array.isArray(detail)) {
                const msg = detail
                    .map(item => {
                        const nested = item?.ctx?.error;
                        const raw = typeof nested === 'string' ? nested : (item?.msg || '');
                        return raw.replace(/^Value error,\s*/i, '') || JSON.stringify(item);
                    })
                    .join(' | ');
                return msg || JSON.stringify(payload);
            }
            if (typeof detail === 'string') return detail;
            if (payload?.error_message && typeof payload.error_message === 'string') {
                return payload.error_message;
            }
            return JSON.stringify(payload);
        } catch (_) {
            // fall through to text
        }
    }
    try {
        return await res.text();
    } catch (_) {
        return `HTTP ${res.status}`;
    }
}

const ApiService = {
    async startScan(target, type) {
        try {
            const res = await fetch(`${API_BASE}/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target, target_type: type })
            });
            if (!res.ok) throw new Error(await parseApiError(res));
            return await res.json();
        } catch (err) {
            console.error("Start Scan Error:", err);
            throw err;
        }
    },

    async getSystemStatus() {
        try {
            const res = await fetch(`${API_BASE}/status`);
            return await res.json();
        } catch (err) {
            console.error("API Status Error:", err);
            return null;
        }
    },

    async getModules() {
        try {
            const res = await fetch(`${API_BASE}/modules`);
            if (!res.ok) throw new Error(await parseApiError(res));
            return await res.json();
        } catch (err) {
            console.error("Modules API Error:", err);
            return [];
        }
    },

    async getJobResult(jobId) {
        try {
            const res = await fetch(`${API_BASE}/result/${jobId}`);
            if (!res.ok) throw new Error(await parseApiError(res));
            return await res.json();
        } catch (err) {
            console.error("Job Result Error:", err);
            throw err;
        }
    }
};

window.ApiService = ApiService;
