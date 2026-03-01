/**
 * GuardianX Dashboard — Frontend Application
 * WebSocket client, Chart.js visualizations, and real-time event handling.
 */

// ─── State ───────────────────────────────────────────────────────────────
let ws = null;
let chart = null;
let reconnectAttempts = 0;
const MAX_RECONNECT = 10;
const MAX_FEED_ITEMS = 100;

const state = {
    connected: false,
    events: [],
    threats: [],
    stats: {
        events_processed: 0,
        threats_detected: 0,
        processes_killed: 0,
        processes_suspended: 0,
        start_time: null,
        monitoring_mode: 'Initializing...',
    },
    timeline: {},
};

// ─── DOM References ──────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);

const DOM = {
    statEvents: $('#stat-events'),
    statThreats: $('#stat-threats'),
    statKilled: $('#stat-killed'),
    statSuspended: $('#stat-suspended'),
    threatFeed: $('#threat-feed'),
    eventLog: $('#event-log'),
    eventCount: $('#event-count'),
    connectionStatus: $('#connection-status'),
    connectionText: $('#connection-text'),
    monitoringMode: $('#monitoring-mode'),
    sysMode: $('#sys-mode'),
    sysUptime: $('#sys-uptime'),
    sysWs: $('#sys-ws'),
    uptime: $('#uptime'),
};

// ─── WebSocket Connection ────────────────────────────────────────────────
function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${location.host}/ws/events`;

    ws = new WebSocket(url);

    ws.onopen = () => {
        state.connected = true;
        reconnectAttempts = 0;
        updateConnectionStatus(true);
        console.log('[GuardianX] WebSocket connected');
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleMessage(data);
        } catch (e) {
            console.error('[GuardianX] Parse error:', e);
        }
    };

    ws.onclose = () => {
        state.connected = false;
        updateConnectionStatus(false);
        console.log('[GuardianX] WebSocket disconnected');
        scheduleReconnect();
    };

    ws.onerror = (err) => {
        console.error('[GuardianX] WebSocket error:', err);
    };
}

function scheduleReconnect() {
    if (reconnectAttempts < MAX_RECONNECT) {
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
        reconnectAttempts++;
        console.log(`[GuardianX] Reconnecting in ${delay}ms (attempt ${reconnectAttempts})`);
        setTimeout(connectWebSocket, delay);
    }
}

// ─── Message Handlers ────────────────────────────────────────────────────
function handleMessage(data) {
    switch (data.type) {
        case 'history':
            handleHistory(data);
            break;
        case 'event':
            handleEvent(data.event);
            break;
        case 'ping':
            // Keepalive — just update stats
            break;
    }

    if (data.stats) {
        updateStats(data.stats);
    }
}

function handleHistory(data) {
    if (data.events) {
        data.events.forEach((event) => {
            addEventToFeed(event, false);
        });
    }
}

function handleEvent(event) {
    addEventToFeed(event, true);
    state.events.push(event);
    updateTimelineChart(event);
}

// ─── UI Updates ──────────────────────────────────────────────────────────
function updateStats(stats) {
    state.stats = { ...state.stats, ...stats };

    animateNumber(DOM.statEvents, stats.events_processed || 0);
    animateNumber(DOM.statThreats, stats.threats_detected || 0);
    animateNumber(DOM.statKilled, stats.processes_killed || 0);
    animateNumber(DOM.statSuspended, stats.processes_suspended || 0);

    if (stats.monitoring_mode) {
        DOM.monitoringMode.textContent = stats.monitoring_mode;
        DOM.sysMode.textContent = stats.monitoring_mode;
    }
}

function animateNumber(element, target) {
    const current = parseInt(element.textContent.replace(/,/g, '')) || 0;
    if (current === target) return;

    const duration = 400;
    const start = performance.now();

    function step(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const value = Math.round(current + (target - current) * eased);
        element.textContent = value.toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
}

function addEventToFeed(event, animate) {
    const isThreat = event.type === 'threat' || event.action === 'KILL' || event.action === 'SUSPEND';
    const container = isThreat ? DOM.threatFeed : DOM.eventLog;

    // Remove empty state
    const emptyState = container.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    const item = document.createElement('div');
    item.className = 'event-item';
    if (!animate) item.style.animation = 'none';

    const severity = getSeverity(event);
    const timeStr = formatTime(event.timestamp);

    item.innerHTML = `
        <div class="event-severity ${severity}"></div>
        <div class="event-content">
            <div class="event-title">${escapeHtml(event.action || event.type || 'EVENT')} — PID ${event.pid || '?'}</div>
            <div class="event-detail">${escapeHtml(event.reason || event.filepath || '')}</div>
        </div>
        <div class="event-time">${timeStr}</div>
    `;

    container.insertBefore(item, container.firstChild);

    // Limit feed size
    while (container.children.length > MAX_FEED_ITEMS) {
        container.removeChild(container.lastChild);
    }

    // Update event count badge
    const totalEvents = DOM.eventLog.querySelectorAll('.event-item').length;
    DOM.eventCount.textContent = `${totalEvents} events`;
}

function getSeverity(event) {
    if (event.action === 'KILL') return 'critical';
    if (event.action === 'SUSPEND') return 'warning';
    if (event.type === 'threat') return 'critical';
    if (event.type === 'warning') return 'warning';
    return 'info';
}

function updateConnectionStatus(connected) {
    const badge = DOM.connectionStatus;
    const text = DOM.connectionText;

    if (connected) {
        badge.className = 'status-badge active';
        text.textContent = 'CONNECTED';
        DOM.sysWs.textContent = 'Connected';
    } else {
        badge.className = 'status-badge disconnected';
        text.textContent = 'DISCONNECTED';
        DOM.sysWs.textContent = 'Disconnected';
    }
}

// ─── Timeline Chart ──────────────────────────────────────────────────────
function initChart() {
    const ctx = document.getElementById('timeline-chart');
    if (!ctx) return;

    const now = new Date();
    const labels = [];
    const eventsData = [];
    const threatsData = [];

    for (let i = 23; i >= 0; i--) {
        const d = new Date(now);
        d.setHours(d.getHours() - i);
        labels.push(d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
        eventsData.push(0);
        threatsData.push(0);
    }

    chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [
                {
                    label: 'Events',
                    data: eventsData,
                    backgroundColor: 'hsla(185, 85%, 55%, 0.35)',
                    borderColor: 'hsl(185, 85%, 55%)',
                    borderWidth: 1,
                    borderRadius: 4,
                },
                {
                    label: 'Threats',
                    data: threatsData,
                    backgroundColor: 'hsla(0, 75%, 60%, 0.45)',
                    borderColor: 'hsl(0, 75%, 60%)',
                    borderWidth: 1,
                    borderRadius: 4,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: {
                    labels: {
                        color: 'hsl(215, 15%, 65%)',
                        font: { family: 'Inter', size: 11 },
                        boxWidth: 12,
                        boxHeight: 12,
                        borderRadius: 3,
                        useBorderRadius: true,
                    },
                },
                tooltip: {
                    backgroundColor: 'hsl(220, 20%, 14%)',
                    titleColor: 'hsl(210, 25%, 92%)',
                    bodyColor: 'hsl(215, 15%, 65%)',
                    borderColor: 'hsla(215, 20%, 30%, 0.5)',
                    borderWidth: 1,
                    cornerRadius: 8,
                    titleFont: { family: 'Inter', weight: '600' },
                    bodyFont: { family: 'Inter' },
                },
            },
            scales: {
                x: {
                    ticks: {
                        color: 'hsl(215, 12%, 45%)',
                        font: { family: 'Inter', size: 10 },
                        maxRotation: 0,
                        maxTicksLimit: 12,
                    },
                    grid: { color: 'hsla(215, 20%, 20%, 0.3)' },
                },
                y: {
                    ticks: {
                        color: 'hsl(215, 12%, 45%)',
                        font: { family: 'Inter', size: 10 },
                        stepSize: 1,
                    },
                    grid: { color: 'hsla(215, 20%, 20%, 0.3)' },
                    beginAtZero: true,
                },
            },
        },
    });
}

function updateTimelineChart(event) {
    if (!chart) return;

    const lastIndex = chart.data.labels.length - 1;

    chart.data.datasets[0].data[lastIndex]++;
    if (event.type === 'threat' || event.action === 'KILL') {
        chart.data.datasets[1].data[lastIndex]++;
    }

    chart.update('none');
}

// ─── Uptime Timer ────────────────────────────────────────────────────────
function updateUptime() {
    if (!state.stats.start_time) return;

    const start = new Date(state.stats.start_time);
    const now = new Date();
    const diff = Math.floor((now - start) / 1000);

    const h = String(Math.floor(diff / 3600)).padStart(2, '0');
    const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
    const s = String(diff % 60).padStart(2, '0');

    const str = `${h}:${m}:${s}`;
    DOM.uptime.textContent = str;
    DOM.sysUptime.textContent = str;
}

// ─── Utilities ───────────────────────────────────────────────────────────
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

function formatTime(timestamp) {
    if (!timestamp) return '';
    try {
        const d = new Date(timestamp);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
        return timestamp;
    }
}

// ─── Initialization ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    connectWebSocket();
    setInterval(updateUptime, 1000);

    // Fetch initial status
    fetch('/api/status')
        .then((r) => r.json())
        .then((data) => {
            if (data.stats) updateStats(data.stats);
        })
        .catch(() => { });
});
