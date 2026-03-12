document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const scanForm = document.getElementById('scanForm');
    const targetInput = document.getElementById('targetInput');
    const targetType = document.getElementById('targetType');
    const targetHint = document.getElementById('targetHint');
    const targetTextGroup = document.getElementById('targetTextGroup');
    const imageInputGroup = document.getElementById('imageInputGroup');
    const imageInput = document.getElementById('imageInput');
    const caseSelect = document.getElementById('caseSelect');
    const caseHint = document.getElementById('caseHint');
    const refreshCasesBtn = document.getElementById('refreshCasesBtn');
    const caseTitleInput = document.getElementById('caseTitleInput');
    const caseTagsInput = document.getElementById('caseTagsInput');
    const createCaseBtn = document.getElementById('createCaseBtn');
    const caseCreateStatus = document.getElementById('caseCreateStatus');
    const casesCountBadge = document.getElementById('casesCountBadge');
    const formStatus = document.getElementById('formStatus');
    const startBtn = document.getElementById('startBtn');
    const btnSpinner = document.getElementById('btnSpinner');
    const btnText = document.querySelector('.btn-text');
    const recentScansList = document.getElementById('recentScansList');
    const workspaceTabs = document.getElementById('workspaceTabs');
    const workspaceHelper = document.getElementById('workspaceHelper');
    const workspacePanes = Array.from(document.querySelectorAll('.workspace-pane'));

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
    let activeWorkspace = 'links';
    let recentScans = [];
    const RECENT_SCANS_STORAGE_KEY = 'osint_recent_scans_v2';
    const MAX_RECENT_SCANS = 12;
    const WORKSPACE_HELPER_TEXT = {
        links: 'Review discovered links and pivot quickly.',
        ai: 'Summarized intelligence for analyst decision support.',
        case: 'Case context, tracked targets, and recent notes.',
        debug: 'WebSocket and event-bus telemetry diagnostics.'
    };
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
        image: {
            placeholder: 'Select an image file',
            hint: 'Upload an image to run Vision OSINT pipeline (face detection, reverse-image pivots, and entity extraction).'
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
            const type = targetType.value;
            const isImageMode = type === 'image';
            const imageFile = isImageMode && imageInput && imageInput.files && imageInput.files.length > 0
                ? imageInput.files[0]
                : null;
            const target = isImageMode ? (imageFile ? imageFile.name : '') : targetInput.value.trim();

            if (!target) {
                if (isImageMode && imageInput) {
                    imageInput.setCustomValidity('Please select an image file.');
                    imageInput.reportValidity();
                }
                setFormStatus('Please provide a valid target before starting scan.', 'error');
                return;
            }

            const validationError = isImageMode
                ? validateImageBeforeSubmit(imageFile)
                : validateInputBeforeSubmit(target, type);

            if (validationError) {
                if (isImageMode && imageInput) {
                    imageInput.setCustomValidity(validationError);
                    imageInput.reportValidity();
                } else {
                    targetInput.setCustomValidity(validationError);
                    targetInput.reportValidity();
                }
                logTerminal(`[System] ${validationError}`, "error");
                setFormStatus(validationError, 'error');
                return;
            }
            targetInput.setCustomValidity('');
            if (imageInput) imageInput.setCustomValidity('');

            resetDashboard();
            setLoading(true);
            setFormStatus('Submitting scan request...', 'info');
            logTerminal(`Initiating scan for ${target} [${type}]...`, "info");
            displayTarget.textContent = target;

            try {
                const selectedCaseId = getSelectedCaseId();
                const res = isImageMode
                    ? await ApiService.startImageScan(imageFile, selectedCaseId)
                    : await ApiService.startScan(target, type, selectedCaseId);

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
                addRecentScan({
                    jobId: currentJobId,
                    target,
                    targetType: type,
                    caseId: Number.isInteger(res.case_id) ? res.case_id : selectedCaseId,
                    status: 'running',
                    createdAt: new Date().toISOString()
                });
                setFormStatus(`Job ${trimMiddle(currentJobId, 12)} started successfully.`, 'success');

                progressContainer.classList.remove('hidden');
                progressFill.style.width = '0%';
                progressText.textContent = 'Starting engines...';

                startPolling(currentJobId);
            } catch (err) {
                const friendlyError = toFriendlySubmitError(err.message, type);
                logTerminal(`[System] Failed to start scan: ${friendlyError}`, "error");
                setFormStatus(`Scan start failed: ${friendlyError}`, 'error');
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
        initializeWorkspaceTabs();
        recentScans = loadRecentScans();
        renderRecentScans();
        setFormStatus('Ready. Select target type and start scan.', 'info');
        populateTargetTypes();
        applyTargetInputMeta();
        renderEventDebugPanel();
        syncStatusBadges();
        targetType?.addEventListener('change', () => {
            applyTargetInputMeta();
            setFormStatus('', '');
        });
        targetInput?.addEventListener('input', () => {
            targetInput.setCustomValidity('');
            setFormStatus('', '');
        });
        targetInput?.addEventListener('keydown', (event) => {
            if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                event.preventDefault();
                scanForm?.requestSubmit();
            }
        });
        imageInput?.addEventListener("change", () => {
            imageInput.setCustomValidity("");
            setFormStatus('', '');
        });
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
        recentScansList?.addEventListener('click', handleRecentScansInteraction);
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
        } else if (msg.type === 'job_update') {
            if (msg.job_id && msg.status) {
                updateRecentScanStatus(String(msg.job_id), String(msg.status));
            }
            if (msg.job_id === currentJobId) {
                logTerminal(`[Scan] Status updated to: ${msg.status}`, 'info');
                if (msg.error) {
                    logTerminal(`[Scan] Error: ${msg.error}`, 'error');
                }
                if (msg.status === 'completed' || msg.status === 'error') {
                    finalizeJob(currentJobId);
                }
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

        const preferredOrder = ['domain', 'ip', 'email', 'person_name', 'image', 'username', 'phone'];
        const targetLabels = {
            ip: 'IP Address',
            person_name: 'Person Name',
            image: 'Image',
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
                if (res?.status) {
                    updateRecentScanStatus(jobId, String(res.status));
                }
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
            updateRecentScanStatus(jobId, String(res.status || 'completed'));
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
                setFormStatus(`Job ${trimMiddle(jobId, 12)} completed. AI summary ready.`, 'success');
            } else if (res.status === 'error') {
                aiContent.innerHTML = res.error_message || 'Scan failed before summary generation.';
                setFormStatus(`Job ${trimMiddle(jobId, 12)} failed.`, 'error');
            } else {
                aiContent.innerHTML = 'Summary is not available yet. Click "Refresh Summary" to check again.';
                setFormStatus(`Job ${trimMiddle(jobId, 12)} completed.`, 'success');
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
            setFormStatus(`Could not load final result for ${trimMiddle(jobId, 12)}.`, 'error');
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
        progressFill.style.width = '0%';
        progressText.textContent = '0 / 0 Modules';
        updateCaseContextDisplay();
        if (graph) {
            try { graph.clear(); } catch (e) { console.error(e); }
        }
        generateAiBtn.classList.add('hidden');
        aiContent.innerHTML = 'Run a scan to generate intelligence. Once completed, you can request an AI summary.';
        setActiveWorkspace('links');
        if (linksContent) {
            linksContent.innerHTML = '<div class="links-empty">Run a scan to collect clickable links from discovered results.</div>';
        }
        if (linksCountBadge) {
            linksCountBadge.textContent = '0';
            linksCountBadge.classList.add('neutral');
            linksCountBadge.classList.remove('online');
        }
    }

    function setFormStatus(message, type = '') {
        if (!formStatus) return;
        const fallback = currentCaseId
            ? `Ready. New scans will attach to Case #${currentCaseId}.`
            : 'Ready. Select target type and start scan.';
        formStatus.textContent = message || fallback;
        formStatus.classList.remove('success', 'error', 'info');
        if (type) {
            formStatus.classList.add(type);
        }
    }

    function initializeWorkspaceTabs() {
        if (!workspaceTabs) return;
        workspaceTabs.addEventListener('click', (event) => {
            const button = event.target.closest('.workspace-tab');
            if (!button) return;
            const workspace = button.getAttribute('data-workspace');
            if (!workspace) return;
            setActiveWorkspace(workspace);
        });
        setActiveWorkspace(activeWorkspace);
    }

    function setActiveWorkspace(workspace) {
        const next = WORKSPACE_HELPER_TEXT[workspace] ? workspace : 'links';
        activeWorkspace = next;

        workspacePanes.forEach((pane) => {
            const paneKey = pane.getAttribute('data-workspace') || '';
            pane.classList.toggle('workspace-hidden', paneKey !== next);
        });

        if (workspaceTabs) {
            const tabs = workspaceTabs.querySelectorAll('.workspace-tab');
            tabs.forEach((tab) => {
                const tabKey = tab.getAttribute('data-workspace') || '';
                const active = tabKey === next;
                tab.classList.toggle('active', active);
                tab.setAttribute('aria-selected', active ? 'true' : 'false');
            });
        }

        if (workspaceHelper) {
            workspaceHelper.textContent = WORKSPACE_HELPER_TEXT[next] || '';
        }
    }

    function handleRecentScansInteraction(event) {
        const trigger = event.target.closest('[data-action]');
        if (!trigger) return;
        const indexRaw = trigger.getAttribute('data-index');
        const index = Number.parseInt(indexRaw || '', 10);
        if (!Number.isInteger(index) || index < 0 || index >= recentScans.length) return;

        const item = recentScans[index];
        const action = trigger.getAttribute('data-action');
        if (action === 'reuse') {
            applyRecentScan(item);
        } else if (action === 'open') {
            openRecentScanResult(item);
        }
    }

    function loadRecentScans() {
        try {
            const raw = window.localStorage.getItem(RECENT_SCANS_STORAGE_KEY);
            if (!raw) return [];
            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) return [];
            return parsed
                .map(normalizeRecentScanItem)
                .filter(Boolean)
                .slice(0, MAX_RECENT_SCANS);
        } catch (_) {
            return [];
        }
    }

    function persistRecentScans() {
        try {
            window.localStorage.setItem(RECENT_SCANS_STORAGE_KEY, JSON.stringify(recentScans.slice(0, MAX_RECENT_SCANS)));
        } catch (_) {
            // best effort only
        }
    }

    function normalizeRecentScanItem(value) {
        if (!value || typeof value !== 'object') return null;
        const target = String(value.target || '').trim();
        const targetType = String(value.targetType || '').trim();
        const jobId = String(value.jobId || '').trim();
        if (!target || !targetType) return null;
        return {
            target,
            targetType,
            jobId: jobId || null,
            caseId: Number.isInteger(value.caseId) ? value.caseId : null,
            status: String(value.status || 'submitted'),
            createdAt: String(value.createdAt || new Date().toISOString())
        };
    }

    function addRecentScan(item) {
        const normalized = normalizeRecentScanItem(item);
        if (!normalized) return;
        recentScans = recentScans.filter((existing) => existing.jobId !== normalized.jobId);
        recentScans.unshift(normalized);
        if (recentScans.length > MAX_RECENT_SCANS) {
            recentScans.length = MAX_RECENT_SCANS;
        }
        persistRecentScans();
        renderRecentScans();
    }

    function updateRecentScanStatus(jobId, status) {
        if (!jobId) return;
        const idx = recentScans.findIndex((item) => item.jobId === jobId);
        if (idx === -1) return;
        recentScans[idx].status = String(status || recentScans[idx].status || 'unknown');
        persistRecentScans();
        renderRecentScans();
    }

    function renderRecentScans() {
        if (!recentScansList) return;
        if (!Array.isArray(recentScans) || recentScans.length === 0) {
            recentScansList.innerHTML = '<div class="recent-empty">No scans yet. Start your first investigation.</div>';
            return;
        }

        recentScansList.innerHTML = recentScans.map((item, index) => {
            const status = String(item.status || 'submitted').toLowerCase();
            const statusClass = status === 'completed'
                ? 'online'
                : status === 'error'
                    ? 'error'
                    : 'neutral';
            const canOpen = item.jobId ? '' : 'disabled';
            const caseText = Number.isInteger(item.caseId) ? `Case #${item.caseId}` : 'Ad-hoc';
            return `
                <div class="recent-item">
                    <div class="recent-item-head">
                        <div class="recent-item-target">${escapeHtml(item.target)}</div>
                        <span class="badge ${statusClass}">${escapeHtml(status)}</span>
                    </div>
                    <div class="recent-item-meta">
                        <span class="case-chip">${escapeHtml(item.targetType)}</span>
                        <span class="case-chip">${escapeHtml(caseText)}</span>
                        <span class="recent-item-time">${escapeHtml(formatRecentTime(item.createdAt))}</span>
                    </div>
                    <div class="recent-item-actions">
                        <span class="recent-job-id">${escapeHtml(item.jobId ? trimMiddle(item.jobId, 20) : 'no job id')}</span>
                        <div>
                            <button type="button" class="btn-mini" data-action="reuse" data-index="${index}">Reuse</button>
                            <button type="button" class="btn-mini" data-action="open" data-index="${index}" ${canOpen}>Open</button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function applyRecentScan(item) {
        if (!item || !targetType) return;
        targetType.value = item.targetType;
        applyTargetInputMeta();

        if (item.targetType === 'image') {
            if (imageInput) {
                imageInput.value = '';
            }
            setFormStatus('Image scans require selecting the file again for browser security.', 'info');
        } else if (targetInput) {
            targetInput.value = item.target || '';
            targetInput.focus();
            targetInput.setSelectionRange(targetInput.value.length, targetInput.value.length);
            setFormStatus('Previous target loaded. Review and start new scan.', 'success');
        }

        if (Number.isInteger(item.caseId)) {
            currentCaseId = item.caseId;
            syncCaseSelectToCurrentCase();
            updateCaseContextDisplay();
            refreshSelectedCaseDetails({ silent: true }).catch((e) => console.error(e));
        }
    }

    function openRecentScanResult(item) {
        if (!item || !item.jobId) return;
        currentJobId = item.jobId;
        finalizedJobId = null;
        displayTarget.textContent = item.target || '-';
        displayJobId.textContent = item.jobId;

        if (Number.isInteger(item.caseId)) {
            currentCaseId = item.caseId;
            syncCaseSelectToCurrentCase();
            updateCaseContextDisplay();
        }

        if (String(item.status).toLowerCase() === 'running') {
            setLoading(true);
            progressContainer.classList.remove('hidden');
            startPolling(item.jobId);
            setFormStatus(`Tracking running job ${trimMiddle(item.jobId, 12)}...`, 'info');
            return;
        }

        setLoading(false);
        finalizeJob(item.jobId).catch((e) => {
            console.error(e);
            setFormStatus(`Could not open job ${trimMiddle(item.jobId || '', 12)}.`, 'error');
        });
    }

    function formatRecentTime(value) {
        if (!value) return '-';
        try {
            return new Date(value).toLocaleString([], {
                year: '2-digit',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                hour12: false
            });
        } catch (_) {
            return '-';
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
        const isImageMode = type === 'image';
        if (!meta) return;

        if (targetTextGroup) {
            targetTextGroup.classList.toggle('hidden', isImageMode);
        }
        if (imageInputGroup) {
            imageInputGroup.classList.toggle('hidden', !isImageMode);
        }

        targetInput.required = !isImageMode;
        if (imageInput) {
            imageInput.required = isImageMode;
        }

        if (!isImageMode) {
            targetInput.placeholder = meta.placeholder;
            if (targetHint) {
                targetHint.textContent = meta.hint;
            }
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

    function validateImageBeforeSubmit(file) {
        if (!file) {
            return 'Please select an image file.';
        }
        const name = String(file.name || '').toLowerCase();
        if (!/\.(jpe?g|png|webp|bmp|gif|tiff?)$/.test(name)) {
            return 'Unsupported image format. Use JPG/PNG/WEBP/BMP/GIF/TIFF.';
        }
        const maxBytes = 15 * 1024 * 1024;
        if (Number(file.size || 0) > maxBytes) {
            return 'Image size exceeds 15 MB upload limit.';
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

            if (moduleName === 'Vision_Image_OSINT') {
                const reverseHits = Array.isArray(data.reverse_image_results) ? data.reverse_image_results : [];
                reverseHits.forEach((hit, idx) => {
                    if (!hit || typeof hit !== 'object') return;
                    addLink(hit.url, `Vision Hit #${idx + 1}`, moduleName);
                });

                const resultUrls = Array.isArray(data.result_urls) ? data.result_urls : [];
                resultUrls.forEach((url, idx) => {
                    addLink(url, `Vision URL #${idx + 1}`, moduleName);
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
