const startBtn = document.querySelector('.Start');
const stopBtn = document.querySelector('.Stop');
const clearBtn = document.querySelector('.Clear');
const analyzeBtn = document.querySelector('.Analyze');
const showNamesBtn = document.querySelector('.btn-names');
const filterBtn = document.querySelector('.btn-filter');
const resetBtn = document.querySelector('.btn-reset');
const showLogsBtn = document.getElementById('showLogsBtn');
const logsContainer = document.getElementById('logsContainer');

const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const recordCount = document.getElementById('recordCount');
const packetCount = document.getElementById('packet_count');
const avgSize = document.getElementById('avg_size');
const tcpSpan = document.getElementById('tcp');
const udpSpan = document.getElementById('udp');
const icmpSpan = document.getElementById('icmp');


let showNames = true;
let monitoring = false;
let refreshInterval = null;
let logsVisible = false;
let logsPage = 100;

stopBtn.disabled = true;


startBtn.onclick = function() {
    if (monitoring) return;

    fetch('/api/start', { method: 'POST' })
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            if (data.status === 'started' || data.status === 'already running') {
                monitoring = true;
                startBtn.disabled = true;
                stopBtn.disabled = false;
                statusDot.classList.add('active');
                statusText.innerText = 'MONITORING...';


                if (refreshInterval) clearInterval(refreshInterval);
                refreshInterval = setInterval(function() {
                    loadData();
                    if (logsVisible) loadLogs();
                }, 2000);
            }
        });
};


stopBtn.onclick = function() {
    fetch('/api/stop', { method: 'POST' })
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            monitoring = false;
            startBtn.disabled = false;
            stopBtn.disabled = true;
            statusDot.classList.remove('active');
            statusText.innerText = 'IDLE';

            if (refreshInterval) {
                clearInterval(refreshInterval);
                refreshInterval = null;
            }

            loadData();
            if (logsVisible) loadLogs();
        });
};


clearBtn.onclick = function() {
    if (confirm('Are you sure? This will delete ALL captured packet data!\n\nNote: the Logs panel is not affected.')) {
        fetch('/api/clear', { method: 'POST' })
            .then(function() {
                logsPage = 100;
                loadData();

            });
    }
};


analyzeBtn.onclick = function() {
    fetch('/api/analyze', { method: 'POST' })
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            loadData();
            if (logsVisible) loadLogs();
        });
};


showNamesBtn.onclick = function() {
    showNames = !showNames;
    showNamesBtn.innerText = showNames ? 'Hide Names' : 'Show Names';
    loadData();
};

filterBtn.onclick = function() {
    loadData();
};

resetBtn.onclick = function() {
    document.getElementById('filterProtocol').value = '';
    document.getElementById('filterSrcIP').value = '';
    document.getElementById('filterDstIP').value = '';
    loadData();

};


showLogsBtn.onclick = function() {
    logsVisible = !logsVisible;

    if (logsVisible) {
        logsContainer.classList.add('visible');
        showLogsBtn.innerText = '✕ Hide Logs';
        showLogsBtn.classList.add('active');
        logsPage = 100;
        loadLogs();

        setTimeout(function() {
            logsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 100);
    } else {
        logsContainer.classList.remove('visible');
        showLogsBtn.innerText = '☰ Show Logs';
        showLogsBtn.classList.remove('active');
    }
};


function loadLogs() {
    fetch('/api/logs')
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            updateLogsTable(data.logs, data.count);
        });
}


function updateLogsTable(logs, totalCount) {
    const tbody = document.getElementById('logsBody');
    const logCountSpan = document.getElementById('logCount');


    logCountSpan.innerText = totalCount + ' entries';

    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="10">No log entries yet. Start monitoring to capture packets.</td></tr>';
        return;
    }


    const visible = logs.slice(0, logsPage);
    const totalRows = logs.length;

    let html = '';
    for (let i = 0; i < visible.length; i++) {
        const p = visible[i];
        const rowNum = i + 1;


        const srcDisplay = p.src_ip_display || p.src_ip;
        const dstDisplay = p.dst_ip_display || p.dst_ip;

        html += '<tr>';
        html += '<td class="log-row-number">' + rowNum + '</td>';
        html += '<td>' + p.timestamp + '</td>';
        html += '<td>' + formatIpWithTag(srcDisplay) + '</td>';
        html += '<td>' + formatIpWithTag(dstDisplay) + '</td>';
        html += '<td>' + p.protocol + '</td>';
        html += '<td>' + p.packet_size + '</td>';
        html += '<td>' + (p.src_port === 'N/A' ? '-' : p.src_port) + '</td>';
        html += '<td>' + (p.dst_port === 'N/A' ? '-' : p.dst_port) + '</td>';
        html += '<td>' + p.service + '</td>';
        html += '</tr>';
    }

    tbody.innerHTML = html;


}


function getStatusClass(status) {
    if (status === 'MALICIOUS') return 'status-malicious';
    if (status === 'SUSPICIOUS') return 'status-suspicious';
    if (status === 'PENDING') return 'status-pending';
    if (status === 'DDOS DETECTED') return 'status-ddos';
    return 'status-normal';
}


function formatIpWithTag(display) {

    const match = display.match(/^\[([^\]]+)\]\s+(.*)/);
    if (!match) return display;

    const tag = match[1];
    const ip = match[2];
    const tagLower = tag.toLowerCase();

    let cssClass = 'tag-server';
    if (tagLower === 'dns') cssClass = 'tag-dns';
    else if (tagLower === 'web') cssClass = 'tag-web';
    else if (tagLower === 'mail') cssClass = 'tag-mail';
    else if (tagLower === 'gw') cssClass = 'tag-gw';
    else if (tagLower === 'db') cssClass = 'tag-db';
    else if (tagLower === 'server') cssClass = 'tag-server';
    else if (tagLower === 'stu') cssClass = 'tag-stu';
    else if (tagLower === 'staff') cssClass = 'tag-staff';
    else if (tagLower === 'admin') cssClass = 'tag-admin';

    return '<span class="' + cssClass + '">[' + tag + ']</span> ' + ip;
}


document.getElementById('loadMoreBtn').onclick = function() {
    logsPage += 100;
    loadLogs();
};


function loadData() {
    // Get filter values
    let protocol = document.getElementById('filterProtocol').value;
    let srcIP = document.getElementById('filterSrcIP').value;
    let dstIP = document.getElementById('filterDstIP').value;


    let url = '/api/data?';
    if (protocol) url += 'protocol=' + protocol + '&';
    if (srcIP) url += 'src_ip=' + srcIP + '&';
    if (dstIP) url += 'dst_ip=' + dstIP + '&';
    url += 'show_names=' + showNames;


    fetch(url)
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            updateTable(data.logs);
            updateStats(data.statistics);
            recordCount.innerText = data.count + ' records';
        });
}


function updateTable(logs) {
    let tbody = document.getElementById('trafficBody');

    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="9">No traffic data. Press START MONITORING.</td></tr>';
        return;
    }

    let html = '';
    for (let i = 0; i < logs.length; i++) {
        let p = logs[i];

        const statusClass = getStatusClass(p.status);

        const srcDisplay = p.src_ip_display || p.src_ip;
        const dstDisplay = p.dst_ip_display || p.dst_ip;

        html += '<tr>';
        html += '<td>' + p.timestamp + '</td>';
        html += '<td>' + formatIpWithTag(srcDisplay) + '</td>';
        html += '<td>' + formatIpWithTag(dstDisplay) + '</td>';
        html += '<td>' + p.protocol + '</td>';
        html += '<td>' + p.packet_size + '</td>';
        html += '<td>' + (p.src_port === 'N/A' ? '-' : p.src_port) + '</td>';
        html += '<td>' + (p.dst_port === 'N/A' ? '-' : p.dst_port) + '</td>';
        html += '<td>' + p.service + '</td>';
        html += '<td class="' + statusClass + '">' + p.status + '</td>';
        html += '</tr>';
    }

    tbody.innerHTML = html;
}


function updateStats(stats) {

    packetCount.innerText = stats.total_packets || 0;


    avgSize.innerText = (stats.avg_packet_size || 0) + ' B';


    let tcp = stats.protocol_counts ? stats.protocol_counts.TCP || 0 : 0;
    let udp = stats.protocol_counts ? stats.protocol_counts.UDP || 0 : 0;
    let icmp = stats.protocol_counts ? stats.protocol_counts.ICMP || 0 : 0;

    tcpSpan.innerText = tcp;
    udpSpan.innerText = udp;
    icmpSpan.innerText = icmp;


    let servicesDiv = document.querySelector('.ports');
    if (servicesDiv) {
        let servicesHtml = '';
        if (stats.top_services && stats.top_services.length > 0) {
            for (let i = 0; i < stats.top_services.length; i++) {
                servicesHtml += '<div>' + stats.top_services[i].name + ': ' + stats.top_services[i].count + '</div>';
            }
        } else {
            servicesHtml = '<div>No data</div>';
        }
        servicesDiv.innerHTML = '<h3 class="port">Top Services</h3>' + servicesHtml;
    }


    let srcDiv = document.querySelector('.source');
    if (srcDiv) {
        let srcHtml = '';
        if (stats.top_src_ips && stats.top_src_ips.length > 0) {
            for (let i = 0; i < stats.top_src_ips.length; i++) {
                let item = stats.top_src_ips[i];
                let displayStr = item.type ? item.type + ' ' + item.ip : item.ip;
                srcHtml += '<div>' + formatIpWithTag(displayStr) + '<span>' + item.count + '</span></div>';
            }
        } else {
            srcHtml = '<div>No data</div>';
        }
        srcDiv.innerHTML = '<h3 class="src">Top Src IPs</h3>' + srcHtml;
    }


    let dstDiv = document.querySelector('.dest');
    if (dstDiv) {
        let dstHtml = '';
        if (stats.top_dst_ips && stats.top_dst_ips.length > 0) {
            for (let i = 0; i < stats.top_dst_ips.length; i++) {
                let item = stats.top_dst_ips[i];
                let displayStr = item.type ? item.type + ' ' + item.ip : item.ip;
                dstHtml += '<div>' + formatIpWithTag(displayStr) + '<span>' + item.count + '</span></div>';
            }
        } else {
            dstHtml = '<div>No data</div>';
        }
        dstDiv.innerHTML = '<h3 class="dst">Top Dest IPs</h3>' + dstHtml;
    }
}


loadData();


setInterval(function() {
    if (!monitoring) {
        loadData();
    }
}, 5000);