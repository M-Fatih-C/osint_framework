document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const scanForm = document.getElementById('scanForm');
    const targetInput = document.getElementById('targetInput');
    const targetType = document.getElementById('targetType');
    const targetHint = document.getElementById('targetHint');
    const startBtn = document.getElementById('startBtn');
    const btnSpinner = document.getElementById('btnSpinner');
    const btnText = document.querySelector('.btn-text');

    const displayTarget = document.getElementById('displayTarget');
    const displayJobId = document.getElementById('displayJobId');
    const terminalOutput = document.getElementById('terminalOutput');
    const activeJobsBadge = document.getElementById('activeJobsBadge');

    const progressContainer = document.getElementById('progressContainer');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');

    // AI Elements
    const generateAiBtn = document.getElementById('generateAiBtn');
    const aiContent = document.getElementById('aiContent');

    // State
    let currentJobId = null;
    let finalizedJobId = null;
    let pollInterval = null;
    let graph = null;

    const TARGET_INPUT_META = {
        domain: {
            placeholder: 'e.g. example.com',
            hint: 'Enter a domain like example.com (not http:// or https://).'
        },
        ip: {
            placeholder: 'e.g. 8.8.8.8',
            hint: 'Enter a valid IPv4 or IPv6 address.'
        },
        email: {
            placeholder: 'e.g. admin@example.com',
            hint: 'Enter a full email address.'
        },
        person_name: {
            placeholder: 'e.g. Muhammet Fatih Cetintas',
            hint: 'Use a real full name (ad soyad). This mode generates person-name OSINT pivots (queries, name variants, username candidates).'
        },
        username: {
            placeholder: 'e.g. fatihcetin',
            hint: 'Username scans expect a handle (letters, numbers, ., _, -) without spaces. Full names are not supported here.'
        },
        phone: {
            placeholder: 'e.g. +90 555 123 4567',
            hint: 'Enter a phone number in local or international format.'
        }
    };

    // --- 1. ALWAYS ATTACH THE FORM SUBMISSION LISTENER FIRST ---
    // This guarantees that clicking the button will never execute the default 
    // page-reload behavior, even if external resources like 'vis-network' fail to load.
    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const target = targetInput.value.trim();
            const type = targetType.value;
            if (!target) return;

            const validationError = validateInputBeforeSubmit(target, type);
            if (validationError) {
                targetInput.setCustomValidity(validationError);
                targetInput.reportValidity();
                logTerminal(`[System] ${validationError}`, "error");
                return;
            }
            targetInput.setCustomValidity('');

            resetDashboard();
            setLoading(true);
            logTerminal(`Initiating scan for ${target} [${type}]...`, "info");
            displayTarget.textContent = target;

            try {
                const res = await ApiService.startScan(target, type);
                currentJobId = res.job_id;
                finalizedJobId = null;
                displayJobId.textContent = currentJobId;
                logTerminal(`[System] Job created with ID: ${currentJobId}`, "success");

                progressContainer.classList.remove('hidden');
                progressFill.style.width = '0%';
                progressText.textContent = 'Starting engines...';

                startPolling(currentJobId);

            } catch (err) {
                logTerminal(`[System] Failed to start scan: ${toFriendlySubmitError(err.message, type)}`, "error");
                setLoading(false);
            }
        });
    }

    // --- 2. INITIALIZE EXTERNAL DEPENDENCIES SAFELY ---
    try {
        if (typeof IntelligenceGraph !== 'undefined') {
            graph = new IntelligenceGraph('networkGraph');
            graph.init();
        } else {
            console.error("IntelligenceGraph class is not defined. (graph.js failed to load)");
        }
    } catch (e) {
        console.error("Failed to initialize Graph visualization:", e);
    }

    try {
        WSService.connect();
        WSService.onMessage(handleSocketMessage);
    } catch (e) {
        console.error("Failed to initialize WebSocket service:", e);
    }

    try {
        populateTargetTypes();
        applyTargetInputMeta();
        targetType?.addEventListener('change', applyTargetInputMeta);
        targetInput?.addEventListener('input', () => targetInput.setCustomValidity(''));
        updateSystemStatus();
        setInterval(updateSystemStatus, 10000); // Poll every 10s
    } catch (e) {
        console.error("Failed to initialize Status Poller:", e);
    }

    // 4. Handlers
    function handleSocketMessage(msg) {
        if (msg.type === 'sys_connect') {
            logTerminal('[System] WebSocket Real-Time connection established.', 'success');
        } else if (msg.type === 'job_update' && msg.job_id === currentJobId) {
            logTerminal(`[Scan] Status updated to: ${msg.status}`, 'info');
            if (msg.error) {
                logTerminal(`[Scan] Error: ${msg.error}`, 'error');
            }
            if (msg.status === 'completed' || msg.status === 'error') {
                finalizeJob(currentJobId);
            }
        } else if (msg.type === 'module_result' && msg.job_id === currentJobId) {
            logTerminal(`[Module] ${msg.module} completed successfully.`, 'success');
            // Update progress
            if (msg.modules_total > 0) {
                const percent = Math.round((msg.modules_done / msg.modules_total) * 100);
                progressFill.style.width = `${percent}%`;
                progressText.textContent = `${msg.modules_done} / ${msg.modules_total} Modules`;
            }
        }
    }

    async function updateSystemStatus() {
        const stats = await ApiService.getSystemStatus();
        if (stats) {
            activeJobsBadge.textContent = stats.jobs_running || 0;
            if (stats.jobs_running > 0) {
                activeJobsBadge.classList.add('online');
                activeJobsBadge.classList.remove('neutral');
            } else {
                activeJobsBadge.classList.add('neutral');
                activeJobsBadge.classList.remove('online');
            }
        }
    }

    async function populateTargetTypes() {
        const modules = await ApiService.getModules();
        if (!Array.isArray(modules) || modules.length === 0) return;

        const preferredOrder = ['domain', 'ip', 'email', 'person_name', 'username', 'phone'];
        const targetLabels = {
            ip: 'IP Address',
            person_name: 'Person Name'
        };
        const discoveredTypes = [...new Set(
            modules.flatMap(m => Array.isArray(m.target_types) ? m.target_types : [])
        )]
            .filter(Boolean)
            .sort((a, b) => {
                const ai = preferredOrder.indexOf(a);
                const bi = preferredOrder.indexOf(b);
                return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi) || a.localeCompare(b);
            });

        if (discoveredTypes.length === 0) return;

        const current = targetType.value;
        targetType.innerHTML = '';
        discoveredTypes.forEach(type => {
            const option = document.createElement('option');
            option.value = type;
            option.textContent = targetLabels[type] || type.charAt(0).toUpperCase() + type.slice(1);
            targetType.appendChild(option);
        });

        if (discoveredTypes.includes(current)) {
            targetType.value = current;
        }

        applyTargetInputMeta();
    }

    function startPolling(jobId) {
        if (pollInterval) clearInterval(pollInterval);

        pollInterval = setInterval(async () => {
            try {
                const res = await ApiService.getJobResult(jobId);
                // Sync progress fallback
                if (res.modules_total > 0) {
                    const done = res.results ? res.results.length : 0;
                    const percent = Math.round((done / res.modules_total) * 100);
                    progressFill.style.width = `${percent}%`;
                    progressText.textContent = `${done} / ${res.modules_total} Modules`;
                }

                // Draw graph incrementally
                if (res.results && res.results.length > 0 && graph) {
                    try {
                        graph.updateFromResults(res.target, res.target_type, res.results);
                    } catch (e) { console.error(e); }
                }

                if (res.status === 'completed' || res.status === 'error') {
                    finalizeJob(jobId);
                }
            } catch (e) {
                console.error("Polling error", e);
            }
        }, 3000);
    }

    async function finalizeJob(jobId) {
        if (!jobId || finalizedJobId === jobId) return;
        if (pollInterval) clearInterval(pollInterval);
        setLoading(false);
        logTerminal(`[System] Job ${jobId} finished.`, 'success');

        try {
            const res = await ApiService.getJobResult(jobId);
            finalizedJobId = jobId;
            if (graph) {
                try {
                    graph.updateFromResults(res.target, res.target_type, res.results);
                } catch (e) { console.error(e); }
            }

            if (res.status === 'error' && res.error_message) {
                logTerminal(`[System] ${res.error_message}`, 'error');
            }

            // Enable AI summary fetch/refresh
            generateAiBtn.classList.remove('hidden');
            generateAiBtn.disabled = false;
            generateAiBtn.textContent = 'Refresh Summary';

            if (res.correlated_intel && res.correlated_intel.summary) {
                aiContent.innerHTML = res.correlated_intel.summary.replace(/\n/g, '<br>');
            } else if (res.status === 'error') {
                aiContent.innerHTML = res.error_message || 'Scan failed before summary generation.';
            } else {
                aiContent.innerHTML = 'Summary is not available yet. Click "Refresh Summary" to check again.';
            }

            // Set up AI Generator click
            generateAiBtn.onclick = async () => {
                generateAiBtn.disabled = true;
                generateAiBtn.textContent = 'Refreshing...';
                aiContent.innerHTML = '<div class="spinner"></div> Fetching latest summary...';

                try {
                    const latest = await ApiService.getJobResult(jobId);
                    if (latest.correlated_intel && latest.correlated_intel.summary) {
                        aiContent.innerHTML = latest.correlated_intel.summary.replace(/\n/g, '<br>');
                        generateAiBtn.textContent = 'Refresh Summary';
                    } else if (latest.error_message) {
                        aiContent.innerHTML = latest.error_message;
                        generateAiBtn.textContent = 'Refresh Summary';
                    } else {
                        aiContent.innerHTML = "Summary is still not ready.";
                        generateAiBtn.textContent = 'Refresh Summary';
                    }
                    generateAiBtn.disabled = false;
                } catch (e) {
                    aiContent.innerHTML = "Error generating AI summary.";
                    generateAiBtn.disabled = false;
                    generateAiBtn.textContent = 'Refresh Summary';
                }
            };

        } catch (e) {
            logTerminal(`[System] Final fetch failed: ${e.message}`, 'error');
        }
    }

    // 5. Utilities
    function logTerminal(message, type = "system") {
        const line = document.createElement('div');
        line.className = `term-line ${type}`;

        const time = new Date().toLocaleTimeString([], { hour12: false });
        line.textContent = `[${time}] ${message}`;

        terminalOutput.appendChild(line);
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }

    function resetDashboard() {
        terminalOutput.innerHTML = '';
        currentJobId = null;
        finalizedJobId = null;
        if (pollInterval) clearInterval(pollInterval);
        progressContainer.classList.add('hidden');
        if (graph) {
            try { graph.clear(); } catch (e) { console.error(e); }
        }
        generateAiBtn.classList.add('hidden');
        aiContent.innerHTML = 'Run a scan to generate intelligence. Once completed, you can request an AI summary.';
    }

    function setLoading(isLoading) {
        if (isLoading) {
            btnText.classList.add('hidden');
            btnSpinner.classList.remove('hidden');
            startBtn.disabled = true;
        } else {
            btnText.classList.remove('hidden');
            btnSpinner.classList.add('hidden');
            startBtn.disabled = false;
        }
    }

    function applyTargetInputMeta() {
        if (!targetType || !targetInput) return;
        const type = targetType.value;
        const meta = TARGET_INPUT_META[type];
        if (!meta) return;

        targetInput.placeholder = meta.placeholder;
        if (targetHint) {
            targetHint.textContent = meta.hint;
        }
    }

    function validateInputBeforeSubmit(target, type) {
        if (type === 'person_name') {
            if (target.length < 2) {
                return 'Person name is too short.';
            }
            if (!/[A-Za-zÀ-ÖØ-öø-ÿĀ-žÇĞİÖŞÜçğıöşü]/.test(target)) {
                return 'Person name should contain letters.';
            }
            return '';
        }
        if (type !== 'username') return '';
        if (/\s/.test(target)) {
            return 'Username target type expects a handle without spaces. If you want to search a person by full name, this field is not a name search.';
        }
        if (!/^[A-Za-z0-9._-]{2,64}$/.test(target)) {
            return 'Invalid username format. Use a handle like fatihcetin (letters, numbers, ., _, -).';
        }
        return '';
    }

    function toFriendlySubmitError(message, type) {
        if (!message) return 'Unknown error';
        if (type === 'username' && /invalid username format/i.test(message)) {
            return 'Username target type expects a username/handle (example: fatihcetin), not a full name.';
        }
        return message;
    }
});
