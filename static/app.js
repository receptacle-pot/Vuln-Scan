let chart;

function appendLog(type, text, time) {
  const logs = document.getElementById('logs');
  const line = document.createElement('div');
  line.className = `log-line ${type}`;
  line.textContent = `[${time}] ${text}`;
  logs.appendChild(line);
  logs.scrollTop = logs.scrollHeight;
}

function setProgress(value) {
  const bar = document.getElementById('progressBar');
  bar.style.width = `${value}%`;
  bar.textContent = `${value}%`;
}

function renderSummary(result) {
  const counts = result.risk_summary.counts;
  const labels = ['Critical', 'High', 'Medium', 'Low'];
  const values = labels.map(k => counts[k]);
  const totalFindings = values.reduce((a, b) => a + b, 0);

  if (chart) chart.destroy();
  chart = new Chart(document.getElementById('riskChart'), {
    type: 'pie',
    data: totalFindings > 0
      ? { labels, datasets: [{ data: values, backgroundColor: ['#d90429', '#f77f00', '#ffbe0b', '#3a86ff'] }] }
      : { labels: ['No vulnerabilities mapped'], datasets: [{ data: [1], backgroundColor: ['#adb5bd'] }] },
    options: { plugins: { legend: { position: 'bottom' } } }
  });

  const usingFallback = result.scan_engine === 'socket_fallback';
  const commandBlock = usingFallback
    ? '<div class="alert alert-warning"><b>Scan Engine:</b> Socket Fallback (Nmap not available on server)</div>'
    : `<div class="alert alert-light"><b>Scan Engine:</b> Nmap<br><b>Command:</b> <code>${result.nmap_command}</code></div>`;

  const warningBlock = (result.warnings || []).length
    ? `<div class="alert alert-warning"><b>Warnings:</b> ${(result.warnings || []).join(' | ')}</div>`
    : '';

  const errorBlock = result.error
    ? `<div class="alert alert-danger"><b>Error:</b> ${result.error}</div>`
    : '';

  document.getElementById('summaryCards').innerHTML = `
    <div class="alert alert-dark"><b>Overall Risk:</b> ${result.risk_summary.overall}</div>
    <div class="alert alert-secondary"><b>Weighted Score:</b> ${result.risk_summary.weighted_score}</div>
    <div class="alert alert-info"><b>Hosts discovered:</b> ${result.hosts_discovered.length}</div>
    <div class="alert alert-primary"><b>Open ports found:</b> ${result.open_ports.length}</div>
    ${commandBlock}
    ${warningBlock}
    ${errorBlock}
  `;

  document.getElementById('nmapRaw').textContent = result.nmap_raw_output || '';

  const body = document.getElementById('vulnTableBody');
  body.innerHTML = '';
  if (!result.vulnerabilities.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td colspan="5">No vulnerabilities mapped from current scan results. Target may be unreachable or no open ports were found.</td>';
    body.appendChild(tr);
    return;
  }

  result.vulnerabilities.forEach(v => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${v.port}</td><td>${v.service}</td><td>${v.severity}</td><td>${v.cvss_estimate}</td><td>${v.recommendation}</td>`;
    body.appendChild(tr);
  });
}

async function getResult(resultUrl) {
  const res = await fetch(resultUrl);
  const payload = await res.json();
  if (!res.ok) {
    throw new Error(payload.error || 'Failed to fetch scan result');
  }
  return payload.result;
}

document.getElementById('scanBtn').addEventListener('click', async () => {
  const target = document.getElementById('target').value.trim();
  const topPorts = parseInt(document.getElementById('topPorts').value, 10);
  document.getElementById('logs').innerHTML = '';
  setProgress(0);
  document.getElementById('reportLink').classList.add('disabled');
  document.getElementById('nmapRaw').textContent = '';
  document.getElementById('summaryCards').innerHTML = '';
  document.getElementById('vulnTableBody').innerHTML = '';

  const create = await fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, top_ports: topPorts })
  });

  const payload = await create.json();
  if (!create.ok) {
    appendLog('error', payload.error || 'Scan failed to start.', new Date().toLocaleTimeString());
    return;
  }

  const evt = new EventSource(payload.stream_url);
  evt.onmessage = async (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'complete') {
      evt.close();
      let result = null;
      try {
        result = await getResult(payload.result_url);
      } catch (err) {
        appendLog('error', err.message, new Date().toLocaleTimeString());
      }
      if (result) {
        renderSummary(result);
        const reportLink = document.getElementById('reportLink');
        reportLink.href = `/reports/${payload.scan_id}`;
        reportLink.classList.remove('disabled');
      }
      if (data.status === 'failed') {
        appendLog('error', 'Scan finished with errors. Check report details.', new Date().toLocaleTimeString());
      }
      setProgress(100);
      return;
    }

    appendLog(data.type, data.message, data.timestamp || new Date().toLocaleTimeString());
    setProgress(data.progress || 0);
  };
});
