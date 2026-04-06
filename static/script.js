/* ═══════════════════════════════════════════════════════════════════════════
   ThreatVision - Threat Intelligence Platform JavaScript
   ═══════════════════════════════════════════════════════════════════════════ */

// ─── State ────────────────────────────────────────────────────────────────────

let state = {
    currentTab: 'dashboard',
    iocPage: 1,
    correlationPage: 1,
    selectedIoc: null,
    charts: {}
};

// ─── Initialization ───────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initEventListeners();
    loadDashboard();
    startAutoRefresh();
});

function initTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            switchTab(tab);
        });
    });
}

function switchTab(tab) {
    state.currentTab = tab;
    
    // Update button states
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    
    // Update content visibility
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === tab);
    });
    
    // Load tab data
    switch(tab) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'iocs':
            loadIOCs();
            break;
        case 'correlations':
            loadCorrelations();
            break;
        case 'feeds':
            loadFeeds();
            break;
        case 'reports':
            loadReports();
            break;
    }
}

function initEventListeners() {
    // Nav buttons
    document.getElementById('refreshFeedsBtn').addEventListener('click', refreshFeeds);
    document.getElementById('runCorrelationBtn').addEventListener('click', runCorrelation);
    
    // IOC Explorer
    document.getElementById('iocSearchInput').addEventListener('input', debounce(loadIOCs, 300));
    document.querySelectorAll('.chip[data-filter-type]').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('.chip[data-filter-type]').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            loadIOCs();
        });
    });
    document.getElementById('severityFilter').addEventListener('change', loadIOCs);
    document.getElementById('feedFilter').addEventListener('change', loadIOCs);
    document.getElementById('activeOnlyCheckbox').addEventListener('change', loadIOCs);
    
    document.getElementById('addManualIocBtn').addEventListener('click', () => showModal('addIocModal'));
    document.getElementById('exportCsvBtn').addEventListener('click', exportCsv);
    document.getElementById('exportTxtBtn').addEventListener('click', exportTxt);
    
    // Correlations
    document.getElementById('dateFromFilter').addEventListener('change', loadCorrelations);
    document.getElementById('dateToFilter').addEventListener('change', loadCorrelations);
    document.getElementById('verdictFilter').addEventListener('change', loadCorrelations);
    document.getElementById('hostFilter').addEventListener('change', loadCorrelations);
    document.getElementById('generateBriefingBtn').addEventListener('click', generateDailyBriefing);
    
    // Reports
    document.getElementById('generateReportBriefingBtn').addEventListener('click', generateDailyBriefing);
    document.getElementById('runFullCorrelationBtn').addEventListener('click', runFullCorrelationReport);
    
    // Modals
    document.getElementById('closeModal').addEventListener('click', () => hideModal('iocModal'));
    document.getElementById('closeAddModal').addEventListener('click', () => hideModal('addIocModal'));
    document.getElementById('cancelAddBtn').addEventListener('click', () => hideModal('addIocModal'));
    document.getElementById('addIocForm').addEventListener('submit', addManualIoc);
    
    // IOC Modal actions
    document.getElementById('enrichNowBtn').addEventListener('click', enrichCurrentIoc);
    document.getElementById('generateIocReportBtn').addEventListener('click', generateIocReport);
    document.getElementById('copyIocBtn').addEventListener('click', copyIocValue);
    document.getElementById('markFpBtn').addEventListener('click', markAsFalsePositive);
    
    // Click outside modal to close
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) hideModal(modal.id);
        });
    });
}

// ─── API Helpers ──────────────────────────────────────────────────────────────

async function api(endpoint, options = {}) {
    try {
        const response = await fetch(endpoint, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'API Error');
        }
        
        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

function showLoading() {
    document.getElementById('loadingOverlay').classList.add('active');
}

function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('active');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    
    setTimeout(() => toast.remove(), 4000);
}

function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

async function loadDashboard() {
    try {
        const data = await api('/api/dashboard');
        
        // Update KPI cards
        document.getElementById('totalIocs').textContent = data.total_iocs || 0;
        document.getElementById('activeThreats').textContent = data.active_iocs || 0;
        document.getElementById('confirmedCorrelations').textContent = data.confirmed_threats || 0;
        document.getElementById('falsePositives').textContent = data.false_positives || 0;
        
        // Update last updated
        document.getElementById('lastUpdated').textContent = 
            `Last updated: ${new Date().toLocaleTimeString()}`;
        
        // Update feed status dots
        updateFeedStatusDots(data.feed_status_list || []);
        
        // Update charts
        updateCharts(data);
        
        // Update recent correlations table
        updateRecentCorrelationsTable(data.recent_correlations || []);
        
    } catch (error) {
        showToast('Failed to load dashboard', 'error');
    }
}

function updateFeedStatusDots(feeds) {
    const container = document.getElementById('feedStatusDots');
    container.innerHTML = feeds.map(feed => {
        const status = feed.status === 'active' ? 'active' : 
                       feed.status === 'error' ? 'error' : 'inactive';
        return `<div class="status-dot ${status}" title="${feed.feed_name}: ${feed.status}"></div>`;
    }).join('');
}

function updateCharts(data) {
    // Destroy existing charts
    Object.values(state.charts).forEach(chart => chart.destroy());
    state.charts = {};
    
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                labels: { color: '#94a3b8' }
            }
        }
    };
    
    // IOCs by Type (Doughnut)
    const iocTypeCtx = document.getElementById('iocTypeChart').getContext('2d');
    const iocTypes = data.iocs_by_type || {};
    state.charts.iocType = new Chart(iocTypeCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(iocTypes),
            datasets: [{
                data: Object.values(iocTypes),
                backgroundColor: ['#3b82f6', '#f97316', '#23d160', '#a855f7', '#ff3860']
            }]
        },
        options: chartOptions
    });
    
    // Threat Level Distribution (Bar)
    const threatLevelCtx = document.getElementById('threatLevelChart').getContext('2d');
    const levels = data.threat_level_distribution || {};
    const levelOrder = ['Critical', 'High', 'Medium', 'Low'];
    state.charts.threatLevel = new Chart(threatLevelCtx, {
        type: 'bar',
        data: {
            labels: levelOrder,
            datasets: [{
                label: 'IOCs',
                data: levelOrder.map(l => levels[l] || 0),
                backgroundColor: ['#ff3860', '#f97316', '#ffdd57', '#23d160']
            }]
        },
        options: {
            ...chartOptions,
            scales: {
                y: { 
                    beginAtZero: true,
                    ticks: { color: '#94a3b8' },
                    grid: { color: '#2d3748' }
                },
                x: { 
                    ticks: { color: '#94a3b8' },
                    grid: { display: false }
                }
            }
        }
    });
    
    // Timeline (Line)
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    const timeline = data.timeline_data || [];
    state.charts.timeline = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: timeline.map(t => t.date),
            datasets: [{
                label: 'New IOCs',
                data: timeline.map(t => t.count),
                borderColor: '#00d4ff',
                backgroundColor: 'rgba(0, 212, 255, 0.1)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            ...chartOptions,
            scales: {
                y: { 
                    beginAtZero: true,
                    ticks: { color: '#94a3b8' },
                    grid: { color: '#2d3748' }
                },
                x: { 
                    ticks: { color: '#94a3b8' },
                    grid: { display: false }
                }
            }
        }
    });
    
    // Top Malware Families (Horizontal Bar)
    const malwareCtx = document.getElementById('malwareFamilyChart').getContext('2d');
    const families = data.top_malware_families || [];
    state.charts.malware = new Chart(malwareCtx, {
        type: 'bar',
        data: {
            labels: families.map(f => f.name || 'Unknown'),
            datasets: [{
                label: 'IOC Count',
                data: families.map(f => f.count),
                backgroundColor: '#00d4ff'
            }]
        },
        options: {
            ...chartOptions,
            indexAxis: 'y',
            scales: {
                x: { 
                    beginAtZero: true,
                    ticks: { color: '#94a3b8' },
                    grid: { color: '#2d3748' }
                },
                y: { 
                    ticks: { color: '#94a3b8' },
                    grid: { display: false }
                }
            }
        }
    });
}

function updateRecentCorrelationsTable(correlations) {
    const tbody = document.getElementById('recentCorrelationsTable');
    
    if (correlations.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #64748b;">No correlations found. Try loading demo data or running correlation.</td></tr>';
        return;
    }
    
    tbody.innerHTML = correlations.map(corr => {
        const logEntry = typeof corr.log_entry === 'string' ? 
            JSON.parse(corr.log_entry) : corr.log_entry || {};
        const verdictClass = getVerdictClass(corr.verdict);
        
        return `
            <tr class="${verdictClass}">
                <td>${formatTime(corr.matched_at)}</td>
                <td class="ioc-value">${defang(corr.ioc_value || '')}</td>
                <td><span class="badge badge-type">${corr.ioc_type || ''}</span></td>
                <td>${corr.malware_family || '-'}</td>
                <td>${logEntry.hostname || '-'}</td>
                <td>${renderThreatScore(corr.threat_score)}</td>
                <td><span class="badge ${getBadgeClass(corr.verdict)}">${corr.verdict || '-'}</span></td>
                <td><button class="btn btn-secondary" onclick="openIocModal(${corr.ioc_id})">Investigate</button></td>
            </tr>
        `;
    }).join('');
}

// ─── IOC Explorer ─────────────────────────────────────────────────────────────

async function loadIOCs() {
    try {
        const typeFilter = document.querySelector('.chip[data-filter-type].active')?.dataset.filterType;
        const params = new URLSearchParams({
            page: state.iocPage,
            limit: 50,
            search: document.getElementById('iocSearchInput').value,
            severity: document.getElementById('severityFilter').value,
            feed: document.getElementById('feedFilter').value,
            active_only: document.getElementById('activeOnlyCheckbox').checked
        });
        
        if (typeFilter && typeFilter !== 'all') {
            params.set('type', typeFilter);
        }
        
        const data = await api(`/api/iocs?${params}`);
        
        renderIOCTable(data.iocs || []);
        renderPagination('iocPagination', data.page, data.pages, (p) => {
            state.iocPage = p;
            loadIOCs();
        });
        
    } catch (error) {
        showToast('Failed to load IOCs', 'error');
    }
}

function renderIOCTable(iocs) {
    const tbody = document.getElementById('iocTable');
    
    if (iocs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #64748b;">No IOCs found. Load demo data to see examples.</td></tr>';
        return;
    }
    
    tbody.innerHTML = iocs.map(ioc => `
        <tr>
            <td class="ioc-value">${defang(ioc.ioc_value)}</td>
            <td><span class="badge badge-type">${ioc.ioc_type}</span></td>
            <td><span class="badge badge-${ioc.severity?.toLowerCase()}">${ioc.severity}</span></td>
            <td>${ioc.source_feed || '-'}</td>
            <td>${ioc.threat_type || '-'}</td>
            <td>${renderConfidenceBar(ioc.confidence)}</td>
            <td>${formatDate(ioc.first_seen)}</td>
            <td><button class="btn btn-secondary" onclick="openIocModal(${ioc.id})">Details</button></td>
        </tr>
    `).join('');
}

function renderConfidenceBar(confidence) {
    return `
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: ${confidence}%"></div>
            </div>
            <span style="font-size: 0.8rem;">${confidence}%</span>
        </div>
    `;
}

function renderPagination(containerId, currentPage, totalPages, onPageChange) {
    const container = document.getElementById(containerId);
    
    if (totalPages <= 1) {
        container.innerHTML = '';
        return;
    }
    
    container.innerHTML = `
        <button ${currentPage <= 1 ? 'disabled' : ''} onclick="this.blur()">Previous</button>
        <span>Page ${currentPage} of ${totalPages}</span>
        <button ${currentPage >= totalPages ? 'disabled' : ''} onclick="this.blur()">Next</button>
    `;
    
    container.querySelector('button:first-child').addEventListener('click', () => {
        if (currentPage > 1) onPageChange(currentPage - 1);
    });
    
    container.querySelector('button:last-child').addEventListener('click', () => {
        if (currentPage < totalPages) onPageChange(currentPage + 1);
    });
}

async function openIocModal(iocId) {
    try {
        showLoading();
        const ioc = await api(`/api/iocs/${iocId}`);
        state.selectedIoc = ioc;
        
        // Update modal header
        document.getElementById('modalIocValue').textContent = defang(ioc.ioc_value);
        
        // Update profile table
        document.getElementById('iocProfile').innerHTML = `
            <tr><td>Type</td><td><span class="badge badge-type">${ioc.ioc_type}</span></td></tr>
            <tr><td>Severity</td><td><span class="badge badge-${ioc.severity?.toLowerCase()}">${ioc.severity}</span></td></tr>
            <tr><td>Confidence</td><td>${ioc.confidence}%</td></tr>
            <tr><td>Source Feed</td><td>${ioc.source_feed || '-'}</td></tr>
            <tr><td>Threat Type</td><td>${ioc.threat_type || '-'}</td></tr>
            <tr><td>Malware Family</td><td>${ioc.malware_family || '-'}</td></tr>
            <tr><td>First Seen</td><td>${formatDate(ioc.first_seen)}</td></tr>
            <tr><td>Last Seen</td><td>${formatDate(ioc.last_seen)}</td></tr>
            <tr><td>Tags</td><td>${(ioc.tags || []).join(', ') || '-'}</td></tr>
        `;
        
        // Update enrichment data
        renderEnrichmentData(ioc);
        
        // Update correlations table
        const corrTbody = document.getElementById('modalCorrelations');
        const correlations = ioc.correlations || [];
        
        if (correlations.length === 0) {
            corrTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #64748b;">No correlations found</td></tr>';
        } else {
            corrTbody.innerHTML = correlations.map(corr => {
                const logEntry = typeof corr.log_entry === 'string' ? 
                    JSON.parse(corr.log_entry) : corr.log_entry || {};
                return `
                    <tr>
                        <td>${logEntry.hostname || '-'}</td>
                        <td>${logEntry.user || logEntry.username || '-'}</td>
                        <td>${formatTime(corr.matched_at)}</td>
                        <td><span class="badge ${getBadgeClass(corr.verdict)}">${corr.verdict || '-'}</span></td>
                    </tr>
                `;
            }).join('');
        }
        
        // Clear IOC report area
        document.getElementById('iocReportArea').style.display = 'none';
        document.getElementById('iocReportContent').innerHTML = '';
        
        showModal('iocModal');
    } catch (error) {
        showToast('Failed to load IOC details', 'error');
    } finally {
        hideLoading();
    }
}

function renderEnrichmentData(ioc) {
    const container = document.getElementById('enrichmentData');
    
    if (!ioc.enriched || !ioc.enrichment_data) {
        container.innerHTML = `
            <p style="color: #64748b;">No enrichment data available.</p>
            <button class="btn btn-primary" id="enrichNowBtn" onclick="enrichCurrentIoc()">Enrich Now</button>
        `;
        return;
    }
    
    const data = ioc.enrichment_data;
    let html = '';
    
    if (data.mock_data) {
        html += '<p style="color: #ffdd57; font-size: 0.8rem; margin-bottom: 1rem;">⚠️ Demo mode: showing mock enrichment data</p>';
    }
    
    // VirusTotal data
    if (data.virustotal) {
        const vt = data.virustotal;
        const ratio = vt.detection_ratio || 'N/A';
        const [detected, total] = ratio.split('/').map(Number);
        const percentage = total ? (detected / total * 100) : 0;
        
        html += `
            <div class="enrichment-section">
                <h4>VirusTotal</h4>
                <div class="detection-ratio">
                    <div class="detection-bar">
                        <div class="detection-fill" style="width: ${percentage}%"></div>
                    </div>
                    <span class="detection-text">${ratio}</span>
                </div>
                ${vt.malware_names?.length ? `<p style="font-size: 0.85rem;">Detections: ${vt.malware_names.slice(0,3).join(', ')}</p>` : ''}
                ${vt.country ? `<p style="font-size: 0.85rem;">Country: ${vt.country}</p>` : ''}
            </div>
        `;
    }
    
    // AbuseIPDB data
    if (data.abuseipdb) {
        const abuse = data.abuseipdb;
        html += `
            <div class="enrichment-section">
                <h4>AbuseIPDB</h4>
                <p style="font-size: 0.9rem;">Abuse Score: <strong style="color: ${abuse.abuse_confidence_score > 50 ? '#ff3860' : '#23d160'}">${abuse.abuse_confidence_score}%</strong></p>
                <p style="font-size: 0.85rem;">Total Reports: ${abuse.total_reports}</p>
                ${abuse.isp ? `<p style="font-size: 0.85rem;">ISP: ${abuse.isp}</p>` : ''}
                ${abuse.country_code ? `<p style="font-size: 0.85rem;">Country: ${abuse.country_code}</p>` : ''}
            </div>
        `;
    }
    
    container.innerHTML = html || '<p style="color: #64748b;">Enrichment data available but empty.</p>';
}

async function enrichCurrentIoc() {
    if (!state.selectedIoc) return;
    
    try {
        showLoading();
        await api('/api/enrich', {
            method: 'POST',
            body: JSON.stringify({ ioc_ids: [state.selectedIoc.id] })
        });
        
        showToast('IOC enriched successfully', 'success');
        
        // Reload IOC modal
        openIocModal(state.selectedIoc.id);
        
    } catch (error) {
        showToast('Failed to enrich IOC', 'error');
    } finally {
        hideLoading();
    }
}

async function generateIocReport() {
    if (!state.selectedIoc) return;
    
    try {
        showLoading();
        const data = await api('/api/briefing/ioc', {
            method: 'POST',
            body: JSON.stringify({ ioc_id: state.selectedIoc.id })
        });
        
        document.getElementById('iocReportArea').style.display = 'block';
        document.getElementById('iocReportContent').innerHTML = renderMarkdown(data.briefing);
        
        showToast('Report generated', 'success');
        
    } catch (error) {
        showToast('Failed to generate report', 'error');
    } finally {
        hideLoading();
    }
}

function copyIocValue() {
    if (!state.selectedIoc) return;
    
    navigator.clipboard.writeText(state.selectedIoc.ioc_value)
        .then(() => showToast('IOC copied to clipboard', 'success'))
        .catch(() => showToast('Failed to copy', 'error'));
}

async function markAsFalsePositive() {
    if (!state.selectedIoc) return;
    
    if (!confirm('Mark this IOC as a false positive?')) return;
    
    try {
        showLoading();
        await api(`/api/iocs/${state.selectedIoc.id}/fp`, { method: 'POST' });
        
        showToast('Marked as false positive', 'success');
        hideModal('iocModal');
        loadIOCs();
        
    } catch (error) {
        showToast('Failed to update IOC', 'error');
    } finally {
        hideLoading();
    }
}

async function addManualIoc(e) {
    e.preventDefault();
    
    const data = {
        ioc_value: document.getElementById('newIocValue').value,
        ioc_type: document.getElementById('newIocType').value,
        threat_type: document.getElementById('newThreatType').value,
        severity: document.getElementById('newSeverity').value,
        malware_family: document.getElementById('newMalwareFamily').value || null
    };
    
    try {
        showLoading();
        await api('/api/iocs/manual', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        
        showToast('IOC added successfully', 'success');
        hideModal('addIocModal');
        document.getElementById('addIocForm').reset();
        loadIOCs();
        
    } catch (error) {
        showToast(error.message || 'Failed to add IOC', 'error');
    } finally {
        hideLoading();
    }
}

function exportCsv() {
    window.location.href = '/api/export/csv';
    showToast('Downloading CSV...', 'info');
}

function exportTxt() {
    window.location.href = '/api/export/txt';
    showToast('Downloading TXT...', 'info');
}

// ─── Correlations ─────────────────────────────────────────────────────────────

async function loadCorrelations() {
    try {
        const params = new URLSearchParams({
            page: state.correlationPage,
            limit: 50,
            verdict: document.getElementById('verdictFilter').value,
            date_from: document.getElementById('dateFromFilter').value,
            date_to: document.getElementById('dateToFilter').value
        });
        
        const data = await api(`/api/correlations?${params}`);
        
        renderCorrelationsTable(data.correlations || []);
        renderPagination('correlationsPagination', data.page, data.pages, (p) => {
            state.correlationPage = p;
            loadCorrelations();
        });
        
        // Populate host filter
        populateHostFilter(data.correlations || []);
        
    } catch (error) {
        showToast('Failed to load correlations', 'error');
    }
}

function renderCorrelationsTable(correlations) {
    const tbody = document.getElementById('correlationsTable');
    
    if (correlations.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" style="text-align: center; color: #64748b;">No correlations found</td></tr>';
        return;
    }
    
    tbody.innerHTML = correlations.map(corr => {
        const logEntry = typeof corr.log_entry === 'string' ? 
            JSON.parse(corr.log_entry) : corr.log_entry || {};
        const verdictClass = getVerdictClass(corr.verdict);
        
        return `
            <tr class="${verdictClass}">
                <td>${formatTime(corr.matched_at)}</td>
                <td class="ioc-value">${defang(corr.ioc_value || '')}</td>
                <td><span class="badge badge-type">${corr.ioc_type || ''}</span></td>
                <td>${corr.malware_family || '-'}</td>
                <td>${logEntry.hostname || '-'}</td>
                <td>${logEntry.user || logEntry.username || '-'}</td>
                <td>${corr.log_source || '-'}</td>
                <td>${renderThreatScore(corr.threat_score)}</td>
                <td><span class="badge ${getBadgeClass(corr.verdict)}">${corr.verdict || '-'}</span></td>
                <td><input type="checkbox" ${corr.reviewed ? 'checked' : ''} onchange="markReviewed(${corr.id}, this.checked)"></td>
            </tr>
        `;
    }).join('');
}

function populateHostFilter(correlations) {
    const hosts = new Set();
    correlations.forEach(corr => {
        const logEntry = typeof corr.log_entry === 'string' ? 
            JSON.parse(corr.log_entry) : corr.log_entry || {};
        if (logEntry.hostname) hosts.add(logEntry.hostname);
    });
    
    const select = document.getElementById('hostFilter');
    const currentValue = select.value;
    select.innerHTML = '<option value="">All Hosts</option>' +
        Array.from(hosts).map(h => `<option value="${h}">${h}</option>`).join('');
    select.value = currentValue;
}

async function markReviewed(corrId, reviewed) {
    try {
        await api(`/api/correlations/${corrId}/reviewed`, {
            method: 'POST',
            body: JSON.stringify({ reviewed })
        });
    } catch (error) {
        showToast('Failed to update', 'error');
    }
}

async function generateDailyBriefing() {
    try {
        showLoading();
        const data = await api('/api/briefing/daily', { method: 'POST' });
        
        document.getElementById('briefingArea').style.display = 'block';
        document.getElementById('briefingMeta').textContent = `Generated at ${formatTime(data.generated_at)}`;
        document.getElementById('briefingContent').innerHTML = renderMarkdown(data.briefing);
        
        showToast('Briefing generated', 'success');
        
    } catch (error) {
        showToast('Failed to generate briefing', 'error');
    } finally {
        hideLoading();
    }
}

// ─── Feeds ────────────────────────────────────────────────────────────────────

async function loadFeeds() {
    try {
        const data = await api('/api/feeds/status');
        renderFeedsGrid(data.feeds || []);
    } catch (error) {
        showToast('Failed to load feeds', 'error');
    }
}

function renderFeedsGrid(feeds) {
    const grid = document.getElementById('feedsGrid');
    
    const feedNames = ['URLhaus', 'ThreatFox', 'Feodo', 'MalwareBazaar', 'Demo'];
    
    grid.innerHTML = feedNames.map(name => {
        const feed = feeds.find(f => f.feed_name === name) || {
            feed_name: name,
            status: 'never_fetched',
            ioc_count: 0,
            last_updated: null
        };
        
        const statusClass = feed.status === 'active' ? 'active' : 
                           feed.status === 'error' ? 'error' : 'never';
        
        return `
            <div class="feed-card">
                <div class="feed-card-header">
                    <span class="feed-card-title">${feed.feed_name}</span>
                    <div class="feed-status-indicator ${statusClass}"></div>
                </div>
                <div class="feed-stats">
                    <div class="feed-stat">
                        <span class="feed-stat-label">Status</span>
                        <span class="feed-stat-value">${feed.status || 'Never fetched'}</span>
                    </div>
                    <div class="feed-stat">
                        <span class="feed-stat-label">Total IOCs</span>
                        <span class="feed-stat-value large">${feed.ioc_count || 0}</span>
                    </div>
                    <div class="feed-stat">
                        <span class="feed-stat-label">Last Updated</span>
                        <span class="feed-stat-value">${feed.last_updated ? formatTime(feed.last_updated) : 'Never'}</span>
                    </div>
                </div>
                <div class="feed-url">${feed.feed_url || '-'}</div>
                <button class="btn btn-secondary" onclick="refreshSingleFeed('${feed.feed_name}')">Refresh This Feed</button>
            </div>
        `;
    }).join('');
}

async function refreshSingleFeed(feedName) {
    try {
        showLoading();
        const data = await api('/api/feeds/refresh', {
            method: 'POST',
            body: JSON.stringify({ feed_name: feedName })
        });
        
        showToast(`${feedName}: ${data.new_iocs_added} new IOCs added`, 'success');
        loadFeeds();
        
    } catch (error) {
        showToast(`Failed to refresh ${feedName}`, 'error');
    } finally {
        hideLoading();
    }
}

async function refreshFeeds() {
    try {
        const btn = document.getElementById('refreshFeedsBtn');
        btn.classList.add('loading');
        
        showLoading();
        const data = await api('/api/feeds/refresh', { method: 'POST' });
        
        showToast(`Feeds refreshed: ${data.new_iocs_added} new IOCs`, 'success');
        
        loadDashboard();
        if (state.currentTab === 'feeds') loadFeeds();
        
    } catch (error) {
        showToast('Failed to refresh feeds', 'error');
    } finally {
        hideLoading();
        document.getElementById('refreshFeedsBtn').classList.remove('loading');
    }
}

async function runCorrelation() {
    try {
        const btn = document.getElementById('runCorrelationBtn');
        btn.classList.add('loading');
        
        showLoading();
        const data = await api('/api/correlate', { method: 'POST' });
        
        showToast(data.summary || 'Correlation complete', 'success');
        
        loadDashboard();
        if (state.currentTab === 'correlations') loadCorrelations();
        
    } catch (error) {
        showToast('Failed to run correlation', 'error');
    } finally {
        hideLoading();
        document.getElementById('runCorrelationBtn').classList.remove('loading');
    }
}

// ─── Reports ──────────────────────────────────────────────────────────────────

async function loadReports() {
    try {
        const data = await api('/api/reports');
        renderReportsList(data.reports || []);
    } catch (error) {
        showToast('Failed to load reports', 'error');
    }
}

function renderReportsList(reports) {
    const container = document.getElementById('reportsList');
    
    if (reports.length === 0) {
        container.innerHTML = '<p style="color: #64748b; text-align: center; padding: 2rem;">No reports yet. Generate a daily briefing to create one.</p>';
        return;
    }
    
    container.innerHTML = reports.map(report => `
        <div class="report-item" onclick="loadReport('${report.report_id}')">
            <div class="report-item-info">
                <h4>${report.report_id}</h4>
                <span>${formatTime(report.generated_at)}</span>
            </div>
            <div class="report-item-stats">
                <div class="report-item-stat">
                    <div class="report-item-stat-value">${report.total_iocs || 0}</div>
                    <div class="report-item-stat-label">IOCs</div>
                </div>
                <div class="report-item-stat">
                    <div class="report-item-stat-value">${report.total_matches || 0}</div>
                    <div class="report-item-stat-label">Correlations</div>
                </div>
                <div class="report-item-stat">
                    <div class="report-item-stat-value" style="color: #ff3860">${report.confirmed_threats || 0}</div>
                    <div class="report-item-stat-label">Threats</div>
                </div>
            </div>
        </div>
    `).join('');
}

async function loadReport(reportId) {
    try {
        showLoading();
        const report = await api(`/api/reports/${reportId}`);
        
        document.getElementById('reportArea').style.display = 'block';
        document.getElementById('reportTitle').textContent = report.report_id;
        
        // Stats
        const stats = report.statistics || report.report_data?.statistics || {};
        document.getElementById('reportStats').innerHTML = `
            <div class="report-stat-card"><div class="value">${stats.total_iocs_tracked || 0}</div><div class="label">IOCs Tracked</div></div>
            <div class="report-stat-card"><div class="value">${stats.correlations_found || 0}</div><div class="label">Correlations</div></div>
            <div class="report-stat-card"><div class="value" style="color: #ff3860">${stats.confirmed_threats || 0}</div><div class="label">Confirmed Threats</div></div>
            <div class="report-stat-card"><div class="value" style="color: #23d160">${stats.false_positives_filtered || 0}</div><div class="label">False Positives</div></div>
        `;
        
        // Briefing
        const briefing = report.ai_briefing || report.report_data?.ai_briefing || '';
        document.getElementById('reportBriefing').innerHTML = renderMarkdown(briefing);
        
        // Download button
        document.getElementById('downloadReportBtn').onclick = () => {
            const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${reportId}.json`;
            a.click();
            URL.revokeObjectURL(url);
        };
        
    } catch (error) {
        showToast('Failed to load report', 'error');
    } finally {
        hideLoading();
    }
}

async function runFullCorrelationReport() {
    try {
        showLoading();
        
        // Run correlation first
        await api('/api/correlate', { method: 'POST' });
        
        // Then generate briefing which creates report
        const data = await api('/api/briefing/daily', { method: 'POST' });
        
        showToast('Report generated', 'success');
        loadReports();
        
        // Load the new report
        if (data.report_id) {
            loadReport(data.report_id);
        }
        
    } catch (error) {
        showToast('Failed to generate report', 'error');
    } finally {
        hideLoading();
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function defang(value) {
    if (!value) return '';
    return value
        .replace(/\./g, '[.]')
        .replace(/@/g, '[@]')
        .replace(/http/gi, 'hxxp');
}

function formatTime(timestamp) {
    if (!timestamp) return '-';
    try {
        return new Date(timestamp).toLocaleString();
    } catch {
        return timestamp;
    }
}

function formatDate(timestamp) {
    if (!timestamp) return '-';
    try {
        return new Date(timestamp).toLocaleDateString();
    } catch {
        return timestamp;
    }
}

function getVerdictClass(verdict) {
    if (!verdict) return '';
    if (verdict.includes('Confirmed')) return 'verdict-confirmed';
    if (verdict.includes('Suspicious')) return 'verdict-suspicious';
    return 'verdict-low';
}

function getBadgeClass(verdict) {
    if (!verdict) return 'badge-type';
    if (verdict.includes('Confirmed')) return 'badge-critical';
    if (verdict.includes('Suspicious')) return 'badge-high';
    return 'badge-medium';
}

function renderThreatScore(score) {
    const level = score >= 90 ? 'critical' : 
                  score >= 70 ? 'high' : 
                  score >= 50 ? 'medium' : 'low';
    return `
        <div class="threat-score">
            <div class="score-bar">
                <div class="score-fill ${level}" style="width: ${score}%"></div>
            </div>
            <span class="score-value">${score}</span>
        </div>
    `;
}

function renderMarkdown(text) {
    if (!text) return '';
    
    // Simple markdown rendering
    return text
        // Headers
        .replace(/^### (.*$)/gim, '<h3>$1</h3>')
        .replace(/^## (.*$)/gim, '<h2>$1</h2>')
        .replace(/^# (.*$)/gim, '<h1>$1</h1>')
        // Bold
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        // Italic
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        // Code
        .replace(/`(.*?)`/g, '<code>$1</code>')
        // Lists
        .replace(/^\- (.*$)/gim, '<li>$1</li>')
        .replace(/^\d+\. (.*$)/gim, '<li>$1</li>')
        // Paragraphs
        .replace(/\n\n/g, '</p><p>')
        // Line breaks
        .replace(/\n/g, '<br>')
        // Wrap in paragraph
        .replace(/^/, '<p>')
        .replace(/$/, '</p>')
        // Clean up list items
        .replace(/<\/li><br><li>/g, '</li><li>')
        .replace(/<p><li>/g, '<ul><li>')
        .replace(/<\/li><\/p>/g, '</li></ul>');
}

function showModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

function hideModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

function startAutoRefresh() {
    // Refresh dashboard every 5 minutes
    setInterval(() => {
        if (state.currentTab === 'dashboard') {
            loadDashboard();
        }
    }, 5 * 60 * 1000);
    
    // Update timestamp every minute
    setInterval(() => {
        document.getElementById('lastUpdated').textContent = 
            `Last updated: ${new Date().toLocaleTimeString()}`;
    }, 60 * 1000);
}

// ─── Demo Data Loading ────────────────────────────────────────────────────────

async function loadDemoData() {
    try {
        showLoading();
        const data = await api('/api/demo/load');
        
        showToast(`Demo loaded: ${data.iocs_loaded} IOCs, ${data.correlations_found} correlations`, 'success');
        
        loadDashboard();
        
    } catch (error) {
        showToast('Failed to load demo data', 'error');
    } finally {
        hideLoading();
    }
}

// Auto-load demo data if no IOCs exist
(async function checkAndLoadDemo() {
    try {
        const data = await api('/api/dashboard');
        if (data.total_iocs === 0) {
            console.log('No IOCs found, loading demo data...');
            loadDemoData();
        }
    } catch (error) {
        console.error('Error checking IOCs:', error);
    }
})();
