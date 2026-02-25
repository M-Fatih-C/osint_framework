document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const scanForm = document.getElementById('scanForm');
    const targetInput = document.getElementById('targetInput');
    const targetType = document.getElementById('targetType');
    const targetHint = document.getElementById('targetHint');
    const caseSelect = document.getElementById('caseSelect');
    const caseHint = document.getElementById('caseHint');
    const refreshCasesBtn = document.getElementById('refreshCasesBtn');
    const caseTitleInput = document.getElementById('caseTitleInput');
    const caseTagsInput = document.getElementById('caseTagsInput');
    const createCaseBtn = document.getElementById('createCaseBtn');
    const caseCreateStatus = document.getElementById('caseCreateStatus');
    const casesCountBadge = document.getElementById('casesCountBadge');
    const startBtn = document.getElementById('startBtn');
    const btnSpinner = document.getElementById('btnSpinner');
    const btnText = document.querySelector('.btn-text');

    const displayTarget = document.getElementById('displayTarget');
    const displayJobId = document.getElementById('displayJobId');
    const displayCaseContext = document.getElementById('displayCaseContext');
    const terminalOutput = document.getElementById('terminalOutput');
    const activeJobsBadge = document.getElementById('activeJobsBadge');
    const queueModeBadgeSide = document.getElementById('queueModeBadgeSide');
    const queueDepthBadgeSide = document.getElementById('queueDepthBadgeSide');
    const wsStatusBadgeSide = document.getElementById('wsStatusBadgeSide');
    const queueModeBadgeTop = document.getElementById('queueModeBadgeTop');
    const queueDepthBadgeTop = document.getElementById('queueDepthBadgeTop');
    const wsStatusBadgeTop = document.getElementById('wsStatusBadgeTop');
    const eventSourceBadgeTop = document.getElementById('eventSourceBadgeTop');

    const progressContainer = document.getElementById('progressContainer');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');

    // AI Elements
    const generateAiBtn = document.getElementById('generateAiBtn');
    const aiContent = document.getElementById('aiContent');
    const linksContent = document.getElementById('linksContent');
    const linksCountBadge = document.getElementById('linksCountBadge');
    const caseDetailsContent = document.getElementById('caseDetailsContent');
    const casePanelStatus = document.getElementById('casePanelStatus');
    const eventDebugSummary = document.getElementById('eventDebugSummary');
    const eventDebugStream = document.getElementById('eventDebugStream');
    const eventDebugTransportBadge = document.getElementById('eventDebugTransportBadge');

    // State
    let currentJobId = null;
    let finalizedJobId = null;
    let pollInterval = null;
    let graph = null;
    let currentCaseId = null;
    let caseList = [];
    let caseDetails = null;
    let caseLoadInFlight = false;
    const eventTelemetry = {
        wsState: 'disconnected',
        queueMode: 'unknown',
        queuePending: null,
        queueProcessing: null,
        totalEvents: 0,
        lastEvent: null,
        recent: [],
        wsClientId: (window.WSService && window.WSService.clientId) ? window.WSService.clientId : null
    };

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
                const selectedCaseId = getSelectedCaseId();
                const res = await ApiService.startScan(target, type, selectedCaseId);
                currentJobId = res.job_id;
                finalizedJobId = null;
                displayJobId.textContent = currentJobId;
                if (typeof res.case_id === 'number') {
                    currentCaseId = res.case_id;
                    await refreshSelectedCaseDetails({ silent: true });
                }
                updateCaseContextDisplay();
                logTerminal(`[System] Job created with ID: ${currentJobId}`, "success");
                if (typeof res.case_id === 'number') {
                    logTerminal(`[System] Job attached to Case #${res.case_id}.`, "info");
                }

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
        renderEventDebugPanel();
        syncStatusBadges();
        targetType?.addEventListener('change', applyTargetInputMeta);
        targetInput?.addEventListener('input', () => targetInput.setCustomValidity(''));
        caseSelect?.addEventListener('change', async () => {
            currentCaseId = getSelectedCaseId();
            setCaseCreateStatus(currentCaseId ? `Selected Case #${currentCaseId}.` : 'No case selected. Scans will run ad-hoc.');
            updateCaseContextDisplay();
            await refreshSelectedCaseDetails({ silent: false });
        });
        refreshCasesBtn?.addEventListener('click', async () => {
            await loadCases({ preserveSelection: true });
        });
        createCaseBtn?.addEventListener('click', async () => {
            await createQuickCase();
        });
        caseTitleInput?.addEventListener('input', () => setCaseCreateStatus(''));
        updateSystemStatus();
        loadCases({ preserveSelection: true }).catch((e) => console.error("Case bootstrap failed", e));
        setInterval(updateSystemStatus, 10000); // Poll every 10s
    } catch (e) {
        console.error("Failed to initialize Status Poller:", e);
    }

    // 4. Handlers
    function handleSocketMessage(msg) {
        recordEventTelemetry(msg);
        if (msg.type === 'sys_connect') {
            setWsConnectionState('connected');
            logTerminal('[System] WebSocket Real-Time connection established.', 'success');
            renderEventDebugPanel();
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
        } else if (msg.type === 'sys_disconnect') {
            setWsConnectionState('disconnected');
            logTerminal('[System] WebSocket disconnected. Auto-reconnect scheduled.', 'error');
            renderEventDebugPanel();
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
            eventTelemetry.queueMode = String(stats.queue_mode || 'in_process');
            eventTelemetry.queuePending = Number.isFinite(stats.queue_pending) ? stats.queue_pending : null;
            eventTelemetry.queueProcessing = Number.isFinite(stats.queue_processing) ? stats.queue_processing : null;
            syncStatusBadges();
            renderEventDebugPanel();
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

                renderDiscoveredLinks(res.results || []);

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
            if (typeof res.case_id === 'number') {
                currentCaseId = res.case_id;
                syncCaseSelectToCurrentCase();
                updateCaseContextDisplay();
                refreshSelectedCaseDetails({ silent: true }).catch((e) => console.error(e));
            }
            if (graph) {
                try {
                    graph.updateFromResults(res.target, res.target_type, res.results);
                } catch (e) { console.error(e); }
            }
            renderDiscoveredLinks(res.results || []);

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
        updateCaseContextDisplay();
        if (graph) {
            try { graph.clear(); } catch (e) { console.error(e); }
        }
        generateAiBtn.classList.add('hidden');
        aiContent.innerHTML = 'Run a scan to generate intelligence. Once completed, you can request an AI summary.';
        if (linksContent) {
            linksContent.innerHTML = '<div class="links-empty">Run a scan to collect clickable links from discovered results.</div>';
        }
        if (linksCountBadge) {
            linksCountBadge.textContent = '0';
            linksCountBadge.classList.add('neutral');
            linksCountBadge.classList.remove('online');
        }
    }

    function setWsConnectionState(state) {
        eventTelemetry.wsState = state === 'connected' ? 'connected' : 'disconnected';
        if (eventDebugTransportBadge) {
            toggleOnlineClass(eventDebugTransportBadge, eventTelemetry.wsState === 'connected');
        }
        syncStatusBadges();
    }

    function syncStatusBadges() {
        const queueModeText = eventTelemetry.queueMode || 'unknown';
        const queueDepthText = `${Number.isFinite(eventTelemetry.queuePending) ? eventTelemetry.queuePending : 0} / ${Number.isFinite(eventTelemetry.queueProcessing) ? eventTelemetry.queueProcessing : 0}`;
        const wsText = eventTelemetry.wsState === 'connected' ? 'Connected' : 'Disconnected';
        const lastSource = eventTelemetry.lastEvent?.source ? shortenSource(eventTelemetry.lastEvent.source) : '-';

        [queueModeBadgeTop, queueModeBadgeSide].forEach(el => {
            if (!el) return;
            el.textContent = queueModeText;
            toggleOnlineClass(el, queueModeText && queueModeText !== 'unknown');
        });
        [queueDepthBadgeTop, queueDepthBadgeSide].forEach(el => {
            if (!el) return;
            el.textContent = queueDepthText;
            const hasWork = (eventTelemetry.queuePending || 0) > 0 || (eventTelemetry.queueProcessing || 0) > 0;
            toggleOnlineClass(el, hasWork);
        });
        [wsStatusBadgeTop, wsStatusBadgeSide].forEach(el => {
            if (!el) return;
            el.textContent = wsText;
            toggleOnlineClass(el, eventTelemetry.wsState === 'connected');
        });
        if (eventSourceBadgeTop) {
            eventSourceBadgeTop.textContent = lastSource;
        }
    }

    function toggleOnlineClass(el, isOnline) {
        el.classList.toggle('online', !!isOnline);
        el.classList.toggle('neutral', !isOnline);
    }

    function recordEventTelemetry(msg) {
        if (!msg || typeof msg !== 'object') return;
        const nowMs = Date.now();
        const meta = (msg._event_meta && typeof msg._event_meta === 'object') ? msg._event_meta : {};
        const sentAtMs = Number.isFinite(meta.sent_at_ms) ? meta.sent_at_ms : null;
        const latencyMs = sentAtMs ? Math.max(0, nowMs - sentAtMs) : null;
        const eventEntry = {
            type: String(msg.type || 'unknown'),
            status: msg.status ? String(msg.status) : null,
            module: msg.module ? String(msg.module) : null,
            jobId: msg.job_id ? String(msg.job_id) : null,
            source: meta.source ? String(meta.source) : null,
            transport: meta.transport ? String(meta.transport) : 'ws_direct',
            bridgeInstance: meta.bridge_instance ? String(meta.bridge_instance) : null,
            channel: meta.channel ? String(meta.channel) : null,
            sentAtMs,
            receivedAtMs: nowMs,
            bridgeDelayMs: Number.isFinite(meta.bridge_delay_ms) ? meta.bridge_delay_ms : null,
            latencyMs
        };

        eventTelemetry.totalEvents += 1;
        eventTelemetry.lastEvent = eventEntry;
        eventTelemetry.recent.unshift(eventEntry);
        if (eventTelemetry.recent.length > 24) {
            eventTelemetry.recent.length = 24;
        }

        if (eventDebugTransportBadge) {
            eventDebugTransportBadge.textContent = eventEntry.transport || 'unknown';
            toggleOnlineClass(eventDebugTransportBadge, eventTelemetry.wsState === 'connected');
        }
        syncStatusBadges();
        renderEventDebugPanel();
    }

    function renderEventDebugPanel() {
        if (!eventDebugSummary || !eventDebugStream) return;

        const last = eventTelemetry.lastEvent;
        const queueMode = eventTelemetry.queueMode || 'unknown';
        const queueDepth = `${Number.isFinite(eventTelemetry.queuePending) ? eventTelemetry.queuePending : 0} pending / ${Number.isFinite(eventTelemetry.queueProcessing) ? eventTelemetry.queueProcessing : 0} processing`;
        const summaryRows = [
            ['WS State', eventTelemetry.wsState === 'connected' ? 'Connected' : 'Disconnected'],
            ['Queue Mode', queueMode],
            ['Queue Depth', queueDepth],
            ['WS Client', eventTelemetry.wsClientId || 'n/a'],
            ['Events Seen', String(eventTelemetry.totalEvents)],
            ['Last Event', last ? `${last.type}${last.status ? ` · ${last.status}` : ''}` : 'n/a'],
            ['Last Source', last?.source || 'n/a'],
            ['Last Transport', last?.transport || 'n/a'],
            ['End-to-End Latency', formatLatency(last?.latencyMs)],
            ['Bridge Delay', formatLatency(last?.bridgeDelayMs)],
            ['Bridge Instance', last?.bridgeInstance || 'n/a'],
            ['Redis Channel', last?.channel || 'n/a']
        ];

        eventDebugSummary.innerHTML = `
            <div class="debug-summary-grid">
                ${summaryRows.map(([label, value]) => `
                    <div class="debug-stat">
                        <div class="debug-stat-label">${escapeHtml(label)}</div>
                        <div class="debug-stat-value ${label.includes('Latency') || label.includes('Client') || label.includes('Source') || label.includes('Instance') || label.includes('Channel') ? 'mono' : ''}">${escapeHtml(value)}</div>
                    </div>
                `).join('')}
            </div>
        `;

        if (!eventTelemetry.recent.length) {
            eventDebugStream.innerHTML = '<div class="debug-empty">No event telemetry received yet.</div>';
            return;
        }

        eventDebugStream.innerHTML = eventTelemetry.recent.map((entry, index) => `
            <div class="debug-row ${index === 0 ? 'latest' : ''}">
                <div class="debug-row-main">
                    <span class="debug-row-type">${escapeHtml(entry.type)}</span>
                    ${entry.status ? `<span class="debug-row-pill">${escapeHtml(entry.status)}</span>` : ''}
                    ${entry.module ? `<span class="debug-row-pill muted">${escapeHtml(entry.module)}</span>` : ''}
                    ${entry.jobId ? `<span class="debug-row-pill mono">${escapeHtml(trimMiddle(entry.jobId, 20))}</span>` : ''}
                </div>
                <div class="debug-row-meta">
                    <span>${escapeHtml(entry.transport || 'ws_direct')}</span>
                    <span class="mono">${escapeHtml(shortenSource(entry.source || 'n/a', 30))}</span>
                    <span>${escapeHtml(formatLatency(entry.latencyMs))}</span>
                    <span class="mono">${escapeHtml(formatEventTime(entry.receivedAtMs))}</span>
                </div>
            </div>
        `).join('');
    }

    function formatLatency(value) {
        if (!Number.isFinite(value)) return 'n/a';
        return `${Math.round(value)} ms`;
    }

    function formatEventTime(epochMs) {
        if (!Number.isFinite(epochMs)) return 'n/a';
        try {
            return new Date(epochMs).toLocaleTimeString([], { hour12: false });
        } catch (_) {
            return 'n/a';
        }
    }

    function shortenSource(value, maxLen = 18) {
        if (!value) return '-';
        const str = String(value);
        if (str.length <= maxLen) return str;
        return `${str.slice(0, Math.max(6, maxLen - 9))}...${str.slice(-6)}`;
    }

    function trimMiddle(value, maxLen = 24) {
        const str = String(value || '');
        if (str.length <= maxLen) return str;
        const head = Math.ceil((maxLen - 3) / 2);
        const tail = Math.floor((maxLen - 3) / 2);
        return `${str.slice(0, head)}...${str.slice(-tail)}`;
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
        if (caseHint) {
            caseHint.textContent = currentCaseId
                ? `This scan will be attached to Case #${currentCaseId}.`
                : 'Attach this scan to a case for grouped history, notes, and pivots.';
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

    function renderDiscoveredLinks(rawResults) {
        if (!linksContent) return;
        const links = collectDiscoveredLinks(rawResults);

        if (linksCountBadge) {
            linksCountBadge.textContent = String(links.length);
            if (links.length > 0) {
                linksCountBadge.classList.remove('neutral');
                linksCountBadge.classList.add('online');
            } else {
                linksCountBadge.classList.add('neutral');
                linksCountBadge.classList.remove('online');
            }
        }

        if (links.length === 0) {
            linksContent.innerHTML = '<div class="links-empty">No clickable links extracted yet. Username (Maigret) and person-name dork modules will appear here automatically.</div>';
            return;
        }

        const wrapper = document.createElement('div');
        wrapper.className = 'links-list';

        links.forEach(item => {
            const card = document.createElement('div');
            card.className = 'link-item';

            const header = document.createElement('div');
            header.className = 'link-item-header';

            const label = document.createElement('div');
            label.className = 'link-item-label';
            label.textContent = item.label || 'Discovered Link';

            const source = document.createElement('div');
            source.className = 'link-item-source';
            source.textContent = item.source || 'Unknown source';

            header.appendChild(label);
            header.appendChild(source);

            const anchor = document.createElement('a');
            anchor.className = 'result-link';
            anchor.href = item.url;
            anchor.target = '_blank';
            anchor.rel = 'noopener noreferrer';
            anchor.textContent = item.url;

            card.appendChild(header);
            card.appendChild(anchor);
            wrapper.appendChild(card);
        });

        linksContent.innerHTML = '';
        linksContent.appendChild(wrapper);
    }

    function collectDiscoveredLinks(rawResults) {
        const output = [];
        const seen = new Set();
        if (!Array.isArray(rawResults)) return output;

        const addLink = (url, label, source) => {
            if (typeof url !== 'string') return;
            const normalizedUrl = url.trim();
            if (!/^https?:\/\//i.test(normalizedUrl)) return;
            const key = normalizedUrl.toLowerCase();
            if (seen.has(key)) return;
            seen.add(key);
            output.push({ url: normalizedUrl, label, source });
        };

        for (const item of rawResults) {
            const moduleName = item?.module || 'Unknown';
            const data = item?.data || {};
            if (!data || typeof data !== 'object') continue;

            if (moduleName === 'Username_Checker') {
                const profiles = Array.isArray(data.profiles) ? data.profiles : [];
                profiles.forEach(profile => {
                    addLink(
                        profile?.url,
                        profile?.site ? `${profile.site} Profile` : 'Profile',
                        moduleName
                    );
                });
            }

            if (moduleName === 'Person_Name_Search_Dorks') {
                const quickLinks = Array.isArray(data.quick_links) ? data.quick_links : [];
                quickLinks.forEach(entry => {
                    if (entry?.google) addLink(entry.google, `${entry.label || 'Query'} (Google)`, moduleName);
                    if (entry?.bing) addLink(entry.bing, `${entry.label || 'Query'} (Bing)`, moduleName);
                });
            }

            if (moduleName === 'Subdomain_Scanner') {
                const subdomains = Array.isArray(data.subdomains) ? data.subdomains : [];
                subdomains.slice(0, 10).forEach(sub => {
                    if (typeof sub === 'string' && /^[A-Za-z0-9.-]+$/.test(sub)) {
                        addLink(`https://${sub}`, `${sub}`, moduleName);
                    }
                });
            }

            // Generic fallback: recursively scan for http(s) URLs in module output.
            scanObjectForUrls(data, (url) => addLink(url, 'Extracted URL', moduleName));
        }

        return output.slice(0, 80);
    }

    function scanObjectForUrls(value, onUrl, seenObjects = new WeakSet()) {
        if (!value) return;

        if (typeof value === 'string') {
            const urlMatches = value.match(/https?:\/\/[^\s"'<>]+/g);
            if (urlMatches) {
                urlMatches.forEach(onUrl);
            }
            return;
        }

        if (typeof value !== 'object') return;
        if (seenObjects.has(value)) return;
        seenObjects.add(value);

        if (Array.isArray(value)) {
            value.forEach(item => scanObjectForUrls(item, onUrl, seenObjects));
            return;
        }

        Object.values(value).forEach(item => scanObjectForUrls(item, onUrl, seenObjects));
    }

    function getSelectedCaseId() {
        if (!caseSelect) return null;
        const raw = caseSelect.value;
        if (!raw) return null;
        const parsed = Number.parseInt(raw, 10);
        return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
    }

    function syncCaseSelectToCurrentCase() {
        if (!caseSelect) return;
        if (typeof currentCaseId === 'number' && currentCaseId > 0) {
            caseSelect.value = String(currentCaseId);
        } else {
            caseSelect.value = '';
        }
    }

    function setCaseCreateStatus(message, type = '') {
        if (!caseCreateStatus) return;
        caseCreateStatus.textContent = message || (currentCaseId
            ? `Selected Case #${currentCaseId}.`
            : 'No case selected. Scans will run ad-hoc.');
        caseCreateStatus.classList.remove('success', 'error');
        if (type) {
            caseCreateStatus.classList.add(type);
        }
    }

    function updateCaseContextDisplay() {
        if (!displayCaseContext) return;
        const selected = caseList.find(c => c && c.id === currentCaseId) || caseDetails;
        if (!currentCaseId || !selected) {
            displayCaseContext.textContent = 'Case: Ad-hoc';
            displayCaseContext.classList.remove('hidden');
            applyTargetInputMeta();
            return;
        }
        displayCaseContext.textContent = `Case #${selected.id}: ${selected.title || 'Untitled Case'}`;
        displayCaseContext.classList.remove('hidden');
        applyTargetInputMeta();
    }

    async function loadCases({ preserveSelection = true, selectCaseId = null } = {}) {
        if (caseLoadInFlight) return;
        caseLoadInFlight = true;
        if (refreshCasesBtn) refreshCasesBtn.disabled = true;
        try {
            const payload = await ApiService.listCases(100);
            const items = Array.isArray(payload?.items) ? payload.items : [];
            caseList = items;

            if (casesCountBadge) {
                casesCountBadge.textContent = String(items.length);
                casesCountBadge.classList.toggle('online', items.length > 0);
                casesCountBadge.classList.toggle('neutral', items.length === 0);
            }

            const previous = preserveSelection ? getSelectedCaseId() : null;
            renderCaseSelectOptions(items);

            let nextCaseId = selectCaseId;
            if (!Number.isInteger(nextCaseId)) {
                nextCaseId = previous;
            }
            if (Number.isInteger(nextCaseId) && items.some(c => c.id === nextCaseId)) {
                currentCaseId = nextCaseId;
                if (caseSelect) caseSelect.value = String(nextCaseId);
            } else {
                currentCaseId = null;
                if (caseSelect) caseSelect.value = '';
            }

            updateCaseContextDisplay();
            await refreshSelectedCaseDetails({ silent: true });
            setCaseCreateStatus('');
        } catch (err) {
            console.error(err);
            setCaseCreateStatus(`Failed to load cases: ${err.message}`, 'error');
            renderCasePanelPlaceholder('Unable to load case workspace. Check API /cases endpoint.');
        } finally {
            caseLoadInFlight = false;
            if (refreshCasesBtn) refreshCasesBtn.disabled = false;
        }
    }

    function renderCaseSelectOptions(items) {
        if (!caseSelect) return;
        const currentValue = caseSelect.value;
        caseSelect.innerHTML = '';

        const adHoc = document.createElement('option');
        adHoc.value = '';
        adHoc.textContent = 'Ad-hoc (No Case)';
        caseSelect.appendChild(adHoc);

        items.forEach(item => {
            const option = document.createElement('option');
            option.value = String(item.id);
            const counts = item.counts || {};
            const scans = Number.isFinite(counts.scans) ? counts.scans : 0;
            option.textContent = `#${item.id} ${item.title} (${scans} scans)`;
            caseSelect.appendChild(option);
        });

        if (currentValue && [...caseSelect.options].some(opt => opt.value === currentValue)) {
            caseSelect.value = currentValue;
        }
    }

    async function createQuickCase() {
        const title = (caseTitleInput?.value || '').trim();
        const tagsRaw = (caseTagsInput?.value || '').trim();
        if (!title) {
            setCaseCreateStatus('Case title is required.', 'error');
            caseTitleInput?.focus();
            return;
        }

        const tags = tagsRaw
            ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean).slice(0, 30)
            : [];

        if (createCaseBtn) createCaseBtn.disabled = true;
        setCaseCreateStatus('Creating case...');
        try {
            const created = await ApiService.createCase({
                title,
                tags,
                priority: 'normal',
            });
            if (caseTitleInput) caseTitleInput.value = '';
            if (caseTagsInput) caseTagsInput.value = '';
            await loadCases({ preserveSelection: false, selectCaseId: created.id });
            setCaseCreateStatus(`Created and selected Case #${created.id}.`, 'success');
            logTerminal(`[Case] Created Case #${created.id}: ${created.title}`, 'success');
        } catch (err) {
            setCaseCreateStatus(`Case create failed: ${err.message}`, 'error');
        } finally {
            if (createCaseBtn) createCaseBtn.disabled = false;
        }
    }

    async function refreshSelectedCaseDetails({ silent = false } = {}) {
        if (!currentCaseId) {
            caseDetails = null;
            renderCasePanelPlaceholder('Select a case to view tracked targets, recent jobs, and analyst notes.');
            updateCaseContextDisplay();
            return;
        }

        if (!silent) {
            renderCasePanelPlaceholder(`Loading Case #${currentCaseId}...`);
        }

        try {
            const detail = await ApiService.getCase(currentCaseId);
            caseDetails = detail;
            renderCaseDetails(detail);
            updateCaseContextDisplay();
        } catch (err) {
            console.error(err);
            renderCasePanelPlaceholder(`Failed to load Case #${currentCaseId}: ${err.message}`);
        }
    }

    function renderCasePanelPlaceholder(message) {
        if (caseDetailsContent) {
            caseDetailsContent.innerHTML = `<div class="case-empty">${escapeHtml(message || 'No case selected.')}</div>`;
        }
        if (casePanelStatus) {
            casePanelStatus.textContent = currentCaseId ? `Case #${currentCaseId}` : 'No Case';
            casePanelStatus.classList.remove('online');
            casePanelStatus.classList.add('neutral');
        }
    }

    function renderCaseDetails(detail) {
        if (!caseDetailsContent || !detail) return;
        const counts = detail.counts || {};
        const tags = Array.isArray(detail.tags) ? detail.tags : [];
        const trackedTargets = Array.isArray(detail.tracked_targets) ? detail.tracked_targets.slice(0, 5) : [];
        const recentJobs = Array.isArray(detail.recent_jobs) ? detail.recent_jobs.slice(0, 5) : [];
        const notes = Array.isArray(detail.notes) ? detail.notes.slice(0, 3) : [];

        if (casePanelStatus) {
            casePanelStatus.textContent = `${detail.status || 'open'} · #${detail.id}`;
            casePanelStatus.classList.remove('neutral');
            casePanelStatus.classList.add('online');
        }

        const tagsHtml = tags.length
            ? tags.map(tag => `<span class="case-chip accent">${escapeHtml(tag)}</span>`).join('')
            : '<span class="case-chip">No tags</span>';

        const trackedHtml = trackedTargets.length
            ? trackedTargets.map(t => `
                <div class="case-list-item">
                    <div class="case-list-item-row">
                        <div class="case-list-item-main">${escapeHtml(t.target || '')}</div>
                        <span class="case-chip">${escapeHtml(t.target_type || 'unknown')}</span>
                    </div>
                    <div class="case-list-item-sub">last_seen: ${escapeHtml(t.last_seen_at || '-')}</div>
                </div>
            `).join('')
            : '<div class="case-empty">No tracked targets yet.</div>';

        const jobsHtml = recentJobs.length
            ? recentJobs.map(j => `
                <div class="case-list-item">
                    <div class="case-list-item-row">
                        <div class="case-list-item-main">${escapeHtml(j.target || '')}</div>
                        <span class="case-chip">${escapeHtml(j.status || 'unknown')}</span>
                    </div>
                    <div class="case-list-item-sub">${escapeHtml(j.target_type || '?')} · ${escapeHtml(j.job_id || '')}</div>
                </div>
            `).join('')
            : '<div class="case-empty">No jobs attached yet.</div>';

        const notesHtml = notes.length
            ? notes.map(n => `
                <div class="case-list-item">
                    <div class="case-list-item-main">${escapeHtml(n.content || '')}</div>
                    <div class="case-list-item-sub">${escapeHtml(n.author || 'unknown')} · ${escapeHtml(n.created_at || '-')}</div>
                </div>
            `).join('')
            : '<div class="case-empty">No notes yet.</div>';

        caseDetailsContent.innerHTML = `
            <div class="case-summary">
                <div class="case-summary-top">
                    <div>
                        <div class="case-summary-title">#${escapeHtml(String(detail.id))} ${escapeHtml(detail.title || 'Untitled Case')}</div>
                        <div class="inline-status">${escapeHtml(detail.description || 'No description')}</div>
                    </div>
                    <div class="case-summary-meta">
                        <span class="case-chip">${escapeHtml(detail.status || 'open')}</span>
                        <span class="case-chip">${escapeHtml(detail.priority || 'normal')}</span>
                        ${tagsHtml}
                    </div>
                </div>
                <div class="case-grid">
                    <div class="case-stat">
                        <div class="case-stat-label">Scans</div>
                        <div class="case-stat-value">${escapeHtml(String(counts.scans || 0))}</div>
                    </div>
                    <div class="case-stat">
                        <div class="case-stat-label">Targets</div>
                        <div class="case-stat-value">${escapeHtml(String(counts.targets || 0))}</div>
                    </div>
                    <div class="case-stat">
                        <div class="case-stat-label">Notes</div>
                        <div class="case-stat-value">${escapeHtml(String(counts.notes || 0))}</div>
                    </div>
                </div>
                <div class="case-section">
                    <div class="case-section-title">Tracked Targets</div>
                    <div class="case-list">${trackedHtml}</div>
                </div>
                <div class="case-section">
                    <div class="case-section-title">Recent Jobs</div>
                    <div class="case-list">${jobsHtml}</div>
                </div>
                <div class="case-section">
                    <div class="case-section-title">Latest Notes</div>
                    <div class="case-list">${notesHtml}</div>
                </div>
            </div>
        `;
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }
});
