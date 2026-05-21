// ShadowFence Dashboard Client
const socket = io();
let alerts = [];
let protocolChart, severityChart, typeChart;

// Connection management
socket.on('connect', () => {
    document.getElementById('connection-status').className = 'status-dot connected';
    document.getElementById('connection-text').textContent = 'Connected';
});

socket.on('disconnect', () => {
    document.getElementById('connection-status').className = 'status-dot disconnected';
    document.getElementById('connection-text').textContent = 'Disconnected';
});

// Handle new alerts
socket.on('new_alert', (alert) => {
    alerts.unshift(alert);
    if (alerts.length > 500) alerts = alerts.slice(0, 500);
    renderAlert(alert);
    updateAlertCounts();
});

// Handle stats updates
socket.on('stats_update', (stats) => {
    updateStatsCards(stats);
    updateCharts(stats);
});

function updateStatsCards(stats) {
    const capture = stats.capture || {};
    const alertStats = stats.alerts || {};

    document.getElementById('packets-captured').textContent = formatNumber(capture.packets_captured || 0);
    document.getElementById('total-alerts').textContent = formatNumber(alertStats.total_alerts || 0);
    document.getElementById('pps').textContent = formatNumber(Math.round(capture.pps || 0));
    document.getElementById('bytes-captured').textContent = formatBytes(capture.bytes_captured || 0);
    document.getElementById('uptime').textContent = formatDuration(capture.elapsed_seconds || 0);

    const bySeverity = alertStats.by_severity || {};
    document.getElementById('critical-alerts').textContent = formatNumber(bySeverity.critical || 0);
}

function renderAlert(alert) {
    const feed = document.getElementById('alert-feed');
    const empty = feed.querySelector('.empty-state');
    if (empty) empty.remove();

    const filter = document.getElementById('severity-filter').value;
    if (filter !== 'all' && alert.severity !== filter) return;

    const item = document.createElement('div');
    item.className = 'alert-item';
    item.setAttribute('data-severity', alert.severity || 'info');

    const time = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'now';

    item.innerHTML = `
        <span class="alert-severity severity-${alert.severity || 'info'}">${(alert.severity || 'info').toUpperCase()}</span>
        <div class="alert-content">
            <div class="alert-type">${escapeHtml(alert.type || 'Unknown')} ${alert.subtype ? '- ' + escapeHtml(alert.subtype) : ''}</div>
            <div class="alert-description">${escapeHtml(alert.description || '')}</div>
            <div class="alert-meta">
                <span>Source: ${escapeHtml(alert.src_ip || '?')}</span>
                <span>Target: ${escapeHtml(alert.dst_ip || '?')}</span>
            </div>
        </div>
        <span class="alert-time">${time}</span>
    `;

    feed.insertBefore(item, feed.firstChild);

    // Keep max 200 items in DOM
    while (feed.children.length > 200) {
        feed.removeChild(feed.lastChild);
    }
}

function updateAlertCounts() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    alerts.forEach(a => {
        const sev = a.severity || 'info';
        if (counts[sev] !== undefined) counts[sev]++;
    });
    document.getElementById('critical-alerts').textContent = formatNumber(counts.critical);
}

// Charts
function initCharts() {
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                position: 'bottom',
                labels: { color: '#94a3b8', font: { size: 12 }, padding: 16 }
            }
        }
    };

    protocolChart = new Chart(document.getElementById('protocol-chart'), {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: ['#3b82f6', '#8b5cf6', '#06b6d4', '#f59e0b', '#22c55e', '#6b7280'],
                borderWidth: 0
            }]
        },
        options: chartOptions
    });

    severityChart = new Chart(document.getElementById('severity-chart'), {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#6b7280'],
                borderWidth: 0
            }]
        },
        options: chartOptions
    });

    typeChart = new Chart(document.getElementById('type-chart'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts',
                data: [],
                backgroundColor: '#3b82f6',
                borderRadius: 4
            }]
        },
        options: {
            ...chartOptions,
            indexAxis: 'y',
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
                y: { ticks: { color: '#94a3b8' }, grid: { display: false } }
            }
        }
    });
}

function updateCharts(stats) {
    const capture = stats.capture || {};
    const alertStats = stats.alerts || {};
    const protocols = capture.protocols || {};
    const bySeverity = alertStats.by_severity || {};
    const byType = alertStats.by_type || {};

    if (protocolChart) {
        protocolChart.data.datasets[0].data = [
            protocols.TCP || 0, protocols.UDP || 0, protocols.ICMP || 0,
            protocols.ARP || 0, protocols.DNS || 0, protocols.Other || 0
        ];
        protocolChart.update('none');
    }

    if (severityChart) {
        severityChart.data.datasets[0].data = [
            bySeverity.critical || 0, bySeverity.high || 0,
            bySeverity.medium || 0, bySeverity.low || 0, bySeverity.info || 0
        ];
        severityChart.update('none');
    }

    if (typeChart) {
        const types = Object.entries(byType).sort((a, b) => b[1] - a[1]).slice(0, 8);
        typeChart.data.labels = types.map(t => t[0]);
        typeChart.data.datasets[0].data = types.map(t => t[1]);
        typeChart.update('none');
    }
}

// Filter
document.getElementById('severity-filter').addEventListener('change', (e) => {
    const filter = e.target.value;
    document.querySelectorAll('.alert-item').forEach(item => {
        if (filter === 'all' || item.getAttribute('data-severity') === filter) {
            item.style.display = '';
        } else {
            item.style.display = 'none';
        }
    });
});

document.getElementById('clear-alerts').addEventListener('click', () => {
    const feed = document.getElementById('alert-feed');
    feed.innerHTML = '<div class="empty-state"><span>&#x1f6e1;</span><p>Alerts cleared. Monitoring continues...</p></div>';
    alerts = [];
});

// Utilities
function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toString();
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

function formatDuration(seconds) {
    if (seconds < 60) return Math.round(seconds) + 's';
    if (seconds < 3600) return Math.round(seconds / 60) + 'm';
    const h = Math.floor(seconds / 3600);
    const m = Math.round((seconds % 3600) / 60);
    return h + 'h ' + m + 'm';
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Poll stats periodically
setInterval(() => {
    fetch('/api/stats')
        .then(r => r.json())
        .then(updateStatsCards)
        .catch(() => {});
    fetch('/api/alerts')
        .then(r => r.json())
        .then(data => {
            if (data.by_severity) updateCharts({ alerts: data, capture: {} });
        })
        .catch(() => {});
}, 2000);

// Initialize
initCharts();
