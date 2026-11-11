/**
 * Core Application Controller for USB Sentinel Station.
 * Manages reactive USB polling, scanning, disinfection, AI war-room, and AI provider settings.
 */

let connectedDevices = [];
let currentScanReport = null;
let lastDangerousFiles = [];

// Tab Navigation
function switchTab(tabId) {
  playClick();
  ['tab-scanner', 'tab-war-room', 'tab-forensics', 'tab-vault', 'tab-cert', 'tab-settings'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.add('hidden');
    const btn = document.getElementById('btn-' + id);
    if (btn) {
      btn.className = "clay-btn clay-btn-neutral text-xs px-5 py-3";
    }
  });

  const activeView = document.getElementById(tabId);
  if (activeView) activeView.classList.remove('hidden');

  const activeBtn = document.getElementById('btn-' + tabId);
  if (activeBtn) {
    activeBtn.className = "clay-btn clay-btn-cyan text-xs px-5 py-3";
  }

  if (tabId === 'tab-settings') {
    loadAISettings();
    loadThreatIntelStats();
  }
}

// Live Digital Clock
setInterval(() => {
  const clockEl = document.getElementById('clock-display');
  if (clockEl) {
    clockEl.innerText = new Date().toLocaleTimeString('id-ID');
  }
}, 1000);

// Hardware USB Polling
async function checkDevices(manual = false) {
  if (manual) {
    playClick();
    const sp = document.getElementById('refresh-spinner');
    if (sp) sp.classList.add('animate-spin');
    setTimeout(() => { if (sp) sp.classList.remove('animate-spin'); }, 800);
  }
  try {
    const apiUrl = window.location.origin.startsWith('http') ? '' : 'http://localhost:8080';
    const res = await fetch(apiUrl + '/api/devices?_t=' + Date.now(), { cache: 'no-store' });
    const data = await res.json();
    connectedDevices = data.devices || [];
    updateDeviceUI(connectedDevices);
  } catch (err) {
    console.debug("Device poll err:", err);
  }
}

function updateDeviceUI(devices) {
  const badge = document.getElementById('device-badge');
  const title = document.getElementById('device-title');
  const subtitle = document.getElementById('device-subtitle');
  const meta = document.getElementById('device-meta-tags');
  const btnScan = document.getElementById('btn-start-scan');
  const unPluggedView = document.getElementById('usb-disconnected-view');
  const pluggedView = document.getElementById('usb-connected-view');

  if (!badge || !title || !subtitle || !btnScan) return;

  if (!devices || devices.length === 0) {
    badge.className = "clay-pill bg-amber-500/20 text-amber-400 border border-amber-500/40";
    badge.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-400 animate-ping inline-block mr-1"></span> 0 Perangkat USB Terhubung';
    title.innerText = "Menunggu Flashdisk Dicolokkan...";
    subtitle.innerText = "Port USB stasiun dalam kondisi standby. Silakan tancapkan flashdisk ke stasiun sanitasi.";
    if (meta) meta.classList.add('hidden');

    btnScan.disabled = true;
    btnScan.classList.add('opacity-50', 'cursor-not-allowed');

    if (unPluggedView) unPluggedView.classList.remove('hidden');
    if (pluggedView) pluggedView.classList.add('hidden');
  } else {
    const dev = devices[0];
    const isMounted = Boolean(dev.mount_point && dev.is_mounted);
    const fsType = (dev.fs_type || 'VFAT').toUpperCase();
    const sizeGb = (dev.size_gb !== undefined && dev.size_gb !== null) ? dev.size_gb : 0;
    const devSerial = dev.serial || 'N/A';
    const devUuid = dev.uuid || 'N/A';
    const devNode = dev.node || '/dev/sda1';
    const devModel = dev.model || dev.label || 'Flash Drive';

    badge.className = "clay-pill bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
    badge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse inline-block mr-1"></span> 1 Flashdisk Siap Diuji';

    title.innerHTML = `Terdeteksi: <span class="text-cyan-400 font-black">${dev.label || devModel}</span>`;
    if (isMounted) {
      subtitle.innerText = `Partisi aktif di ${devNode} terpasang pada ${dev.mount_point}. Siap untuk pembersihan & inspeksi 4-Layer.`;
    } else {
      subtitle.innerText = `Partisi terdeteksi di ${devNode}. Sistem sedang mengaitkan mount point otomatis...`;
    }

    const nEl = document.getElementById('meta-node');
    const uEl = document.getElementById('meta-uuid');
    const sEl = document.getElementById('meta-size');
    const serEl = document.getElementById('meta-serial');
    if (nEl) nEl.innerText = devNode;
    if (uEl) uEl.innerText = `${devUuid} (${fsType})`;
    if (sEl) sEl.innerText = `${sizeGb} GB`;
    if (serEl) serEl.innerText = devSerial;
    if (meta) meta.classList.remove('hidden');

    btnScan.disabled = false;
    btnScan.classList.remove('opacity-50', 'cursor-not-allowed');

    if (unPluggedView) unPluggedView.classList.add('hidden');
    if (pluggedView) pluggedView.classList.remove('hidden');
    const modelText = document.getElementById('disk-model-text');
    if (modelText) modelText.innerText = devModel;
  }
}

// Trigger Live Scan
async function startScan() {
  if (connectedDevices.length === 0) return;
  playTone(700, 0.1);

  const pBox = document.getElementById('scan-progress-box');
  const pBar = document.getElementById('scan-progress-bar');
  const stepLabel = document.getElementById('scan-step-label');
  const pctLabel = document.getElementById('scan-pct-label');
  const btnScan = document.getElementById('btn-start-scan');

  if (pBox) pBox.classList.remove('hidden');
  if (btnScan) btnScan.disabled = true;

  if (stepLabel) stepLabel.innerText = "Layer 1: Device Guard memvalidasi antarmuka USB Mass Storage...";
  if (pBar) pBar.style.width = "25%";
  if (pctLabel) pctLabel.innerText = "25%";

  setTimeout(() => {
    if (stepLabel) stepLabel.innerText = "Layer 2: Scanning Deterministik (Magic Bytes, YARA, Macro, Disguised PE)...";
    if (pBar) pBar.style.width = "55%";
    if (pctLabel) pctLabel.innerText = "55%";
    playTone(600, 0.08);
  }, 500);

  setTimeout(() => {
    if (stepLabel) stepLabel.innerText = "Layer 3: AI Multi-Agent Triage (Static Analyst + Threat Intel + Critic)...";
    if (pBar) pBar.style.width = "85%";
    if (pctLabel) pctLabel.innerText = "85%";
    playTone(750, 0.08);
  }, 1100);

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_node: connectedDevices[0].node })
    });
    const data = await res.json();
    currentScanReport = data;

    if (pBar) pBar.style.width = "100%";
    if (pctLabel) pctLabel.innerText = "100%";
    if (stepLabel) stepLabel.innerText = "Layer 4: Policy Engine menetapkan vonis final!";

    setTimeout(() => {
      if (pBox) pBox.classList.add('hidden');
      if (btnScan) btnScan.disabled = false;
      renderScanReport(data);
    }, 500);

  } catch (err) {
    alert("Gagal scan: " + err);
    if (pBox) pBox.classList.add('hidden');
    if (btnScan) btnScan.disabled = false;
  }
}

// Trigger Disinfection / Cleaning
async function startClean(action = 'quarantine') {
  if (connectedDevices.length === 0) return;
  if (lastDangerousFiles.length === 0) {
    alert("Tidak ada ancaman berbahaya yang perlu dibersihkan!");
    return;
  }

  playTone(500, 0.1);
  const confirmClean = confirm(`Apakah Anda yakin ingin menetralkan & membersihkan ${lastDangerousFiles.length} berkas berbahaya di flashdisk?`);
  if (!confirmClean) return;

  try {
    const res = await fetch('/api/clean', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_node: connectedDevices[0].node,
        action: action,
        dangerous_files: lastDangerousFiles,
        session_id: currentScanReport?.session?.session_id
      })
    });
    const result = await res.json();

    const logBox = document.getElementById('clean-log-box');
    if (logBox) {
      logBox.innerHTML = `
        <div class="text-emerald-400 font-bold">✓ SANITASI BERHASIL DIEKSEKUSI:</div>
        <div>• Berkas Diisolasi ke Karantina : ${result.clean_summary.quarantined.join(', ') || '0'}</div>
        <div>• Berkas Asli Dipulihkan       : ${result.clean_summary.unhidden.join(', ') || 'Tidak ada folder tersembunyi'}</div>
        <div>• Durasi Tindakan Sanitasi     : ${result.clean_summary.duration_s} detik</div>
        <div>• Status Vonis Baru Pasca-Clean: <strong class="text-emerald-400">${result.re_scan.session.action}</strong></div>
      `;
    }

    playSuccessChime();
    renderScanReport(result.re_scan);
    alert("Pembersihan selesai! Flashdisk telah dinetralkan dan diverifikasi aman.");

  } catch (e) {
    alert("Gagal melakukan pembersihan: " + e);
  }
}

// Trigger Quarantine Restore
async function restoreQuarantine() {
  if (connectedDevices.length === 0) return;
  try {
    const res = await fetch('/api/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_node: connectedDevices[0].node })
    });
    const data = await res.json();
    alert(`Pemulihan Selesai! ${data.restored?.length || 0} berkas dikembalikan.`);
    startScan();
  } catch (e) {
    alert("Gagal memulihkan: " + e);
  }
}

// Render Results to UI
function renderScanReport(data) {
  const resultsView = document.getElementById('results-view');
  if (resultsView) resultsView.classList.remove('hidden');

  const isBlock = data.session.action === 'BLOCK';
  const isAllow = data.session.action === 'ALLOW' || data.session.action === 'ALLOW_SANITIZED';

  if (isBlock) playAlarm();
  else playSuccessChime();

  const badgeDec = document.getElementById('badge-decision');
  const titleDec = document.getElementById('text-decision-title');
  const descDec = document.getElementById('text-decision-desc');
  const listReasons = document.getElementById('list-reasons');
  const btnClean = document.getElementById('btn-auto-clean');

  if (badgeDec) badgeDec.innerText = data.session.action;

  if (isBlock) {
    if (badgeDec) badgeDec.className = "clay-pill bg-red-500/20 text-red-300 border border-red-500/40 text-sm";
    if (titleDec) titleDec.innerText = "🔴 FLASHDISK BERBAHAYA! DILARANG MASUK";
    if (descDec) descDec.innerText = "Terdeteksi berkas makro jahat, executable menyamar, atau script obfuscated. Flashdisk wajib ditahan atau dinetralkan.";
    if (btnClean) btnClean.classList.remove('hidden');
  } else if (isAllow) {
    if (badgeDec) badgeDec.className = "clay-pill bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-sm";
    if (titleDec) titleDec.innerText = "🟢 FLASHDISK BERSIH! DIIZINKAN MASUK";
    if (descDec) descDec.innerText = "Seluruh file bersih dari ancaman, makro terisolasi, dan analisis AI menyatakan media aman dibawa ke server room.";
    if (btnClean) btnClean.classList.add('hidden');
  }

  if (listReasons) {
    listReasons.innerHTML = '';
    const allReasons = [...(data.session.deterministic_reasons || []), ...(data.session.ai_reasons || [])];
    allReasons.forEach(r => {
      const li = document.createElement('li');
      li.className = "flex items-start gap-2 text-xs text-slate-300";
      li.innerHTML = `<span class="text-red-400 mt-0.5">•</span> <span>${r}</span>`;
      listReasons.appendChild(li);
    });
  }

  // Populate Files Table
  const tbody = document.getElementById('table-files-body');
  if (tbody) tbody.innerHTML = '';
  lastDangerousFiles = [];

  (data.scanned_files || []).forEach(f => {
    if (f.is_dangerous) lastDangerousFiles.push(f.name);
    if (!tbody) return;

    let hitBadges = '';
    if (f.yara_hits && f.yara_hits.length > 0) {
      hitBadges += f.yara_hits.map(h => `<span class="clay-pill bg-purple-500/20 text-purple-300 text-[10px] ml-1.5 border border-purple-500/40">YARA: ${h}</span>`).join(' ');
    }
    if (f.av_hits && f.av_hits.length > 0) {
      hitBadges += f.av_hits.map(h => `<span class="clay-pill bg-rose-500/20 text-rose-300 text-[10px] ml-1.5 border border-rose-500/40">AV: ${h}</span>`).join(' ');
    }

    const tr = document.createElement('tr');
    tr.className = "border-b border-slate-800/80 hover:bg-slate-800/30 transition-colors";
    tr.innerHTML = `
      <td class="py-3 px-4 font-mono font-bold text-xs ${f.is_dangerous ? 'text-red-400' : 'text-slate-200'}">
        ${f.is_dangerous ? '⚠️ ' : '📄 '} ${f.name} ${hitBadges}
      </td>
      <td class="py-3 px-4 font-mono text-xs text-slate-400 uppercase">${f.type}</td>
      <td class="py-3 px-4 text-xs font-mono text-slate-300">${f.size_bytes} B</td>
      <td class="py-3 px-4 text-xs font-mono ${f.entropy > 6.8 ? 'text-red-400 font-bold' : 'text-slate-400'}">
        ${f.entropy}
      </td>
      <td class="py-3 px-4">
        ${f.is_dangerous ? '<span class="clay-pill bg-red-500/20 text-red-300 border border-red-500/30">DANGEROUS</span>' : '<span class="clay-pill bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">CLEAN</span>'}
      </td>
      <td class="py-3 px-4 text-right">
        <button onclick="openForensicsModal('${f.abs_path}', '${f.name}')" class="clay-btn clay-btn-neutral text-[11px] px-3 py-1.5">
          🔬 Forensik
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  const countBadge = document.getElementById('threat-count-badge');
  if (countBadge) {
    countBadge.innerText = `${lastDangerousFiles.length} Ancaman Aktif`;
    countBadge.className = lastDangerousFiles.length > 0 ? "clay-pill bg-red-500/20 text-red-300" : "clay-pill bg-emerald-500/20 text-emerald-300";
  }

  // Render War Room & Forensics
  renderWarRoom(data);
  renderForensicList(data.scanned_files || []);
  renderCertificate(data);
}

// Render War Room
function renderWarRoom(data) {
  const container = document.getElementById('war-room-dialogs');
  if (!container) return;
  container.innerHTML = '';

  const agentMeta = {
    'static_analyst': { name: 'Static Analyst Agent', icon: '🔍', color: 'text-cyan-400' },
    'intel': { name: 'Threat Intel Agent', icon: '🌐', color: 'text-indigo-400' },
    'critic': { name: 'Adversarial Critic', icon: '⚖️', color: 'text-amber-400' },
    'responder': { name: 'Incident Responder', icon: '📢', color: 'text-emerald-400' }
  };

  (data.agent_runs || []).forEach(run => {
    const meta = agentMeta[run.agent] || { name: run.agent, icon: '🤖', color: 'text-slate-300' };
    const div = document.createElement('div');
    div.className = "clay-card p-5 space-y-3";
    div.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2 font-bold ${meta.color}">
          <span>${meta.icon}</span>
          <span class="text-xs uppercase">${run.agent}</span>
        </div>
        <span class="clay-pill bg-slate-800 text-[10px] text-slate-300 font-mono">${run.status.toUpperCase()}</span>
      </div>
      <p class="text-xs text-slate-300 leading-relaxed font-sans">${run.verdict ? JSON.stringify(run.verdict.reasons || run.verdict) : 'Evaluasi berkas selesai.'}</p>
      <div class="pt-2 border-t border-slate-800/80 flex justify-between text-[10px] text-slate-400 font-mono">
        <span>Tokens: ${run.tokens}</span>
        <span>Latensi: ${run.latency_ms}ms</span>
      </div>
    `;
    container.appendChild(div);
  });

  const responderEl = document.getElementById('txt-war-room-responder');
  if (responderEl) {
    responderEl.innerText =
      data.session.ai_reasons.find(r => r.startsWith('AI:')) || "Pemeriksaan multi-agent selesai dievaluasi dengan aman.";
  }

  const tb = document.getElementById('agent-telemetry-body');
  if (tb) {
    tb.innerHTML = '';
    (data.agent_runs || []).forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="py-2 px-3 text-cyan-300">${r.agent}</td>
        <td class="py-2 px-3 text-slate-400">${r.model}</td>
        <td class="py-2 px-3 text-white font-bold">${r.tokens}</td>
        <td class="py-2 px-3 text-slate-400">${r.latency_ms} ms</td>
        <td class="py-2 px-3 text-emerald-400 font-bold">$${r.cost_est.toFixed(6)}</td>
        <td class="py-2 px-3 text-center"><span class="clay-pill bg-emerald-500/10 text-emerald-400 text-[9px]">${r.status.toUpperCase()}</span></td>
      `;
      tb.appendChild(tr);
    });
  }
}

// Certificate Rendering
function renderCertificate(data) {
  const cId = document.getElementById('cert-id');
  const cNode = document.getElementById('cert-device-node');
  const cSerial = document.getElementById('cert-serial');
  const cTime = document.getElementById('cert-timestamp');
  const cVerd = document.getElementById('cert-verdict');
  const cHead = document.getElementById('cert-head-hash');

  if (cId) cId.innerText = `CERT-SENTINEL-${data.session.session_id.slice(0, 8).toUpperCase()}`;
  if (cNode) cNode.innerText = data.device.node;
  if (cSerial) cSerial.innerText = data.device.serial;
  if (cTime) cTime.innerText = new Date().toISOString();
  if (cVerd) cVerd.innerText = data.session.action;
  if (cHead) cHead.innerText = data.hashchain.head_hash;
}

// =========================================================================
// AI PROVIDER & API KEY SETTINGS CONTROLLER
// =========================================================================

let cachedAISettings = null;

async function loadAISettings() {
  try {
    const res = await fetch('/api/settings/ai');
    const data = await res.json();
    cachedAISettings = data;

    const selectProv = document.getElementById('select-ai-provider');
    if (selectProv) {
      selectProv.value = data.active_provider;
      onProviderSelectChange();
    }

    renderProviderStatusCards(data.providers, data.active_provider);
  } catch (err) {
    console.debug("Failed loading AI settings:", err);
  }
}

function onProviderSelectChange() {
  const selectProv = document.getElementById('select-ai-provider');
  const selectModel = document.getElementById('select-ai-model');
  const keyInput = document.getElementById('input-ai-api-key');
  const provKeyHelp = document.getElementById('help-ai-api-key');

  if (!selectProv || !cachedAISettings) return;
  const currentKey = selectProv.value;
  const provInfo = cachedAISettings.providers[currentKey];

  if (selectModel && provInfo) {
    selectModel.innerHTML = '';
    provInfo.models_available.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m;
      opt.innerText = m;
      if (m === provInfo.model) opt.selected = true;
      selectModel.appendChild(opt);
    });
  }

  if (keyInput && provInfo) {
    keyInput.placeholder = provInfo.masked_key !== "Belum Diatur" ? `Tersimpan: (${provInfo.masked_key})` : "Tempel API Key baru di sini...";
    keyInput.value = '';
  }

  if (provKeyHelp) {
    if (currentKey === 'gemini') {
      provKeyHelp.innerHTML = 'Dapatkan API Key Google Gemini gratis di <a href="https://aistudio.google.com/" target="_blank" class="text-cyan-400 underline">Google AI Studio</a>.';
    } else if (currentKey === 'groq') {
      provKeyHelp.innerHTML = 'Dapatkan API Key Groq Llama-3 di <a href="https://console.groq.com/keys" target="_blank" class="text-cyan-400 underline">Groq Console</a>.';
    } else if (currentKey === 'openai') {
      provKeyHelp.innerHTML = 'Dapatkan API Key OpenAI di <a href="https://platform.openai.com/api-keys" target="_blank" class="text-cyan-400 underline">OpenAI Platform</a>.';
    } else if (currentKey === 'anthropic') {
      provKeyHelp.innerHTML = 'Dapatkan API Key Anthropic Claude di <a href="https://console.anthropic.com/" target="_blank" class="text-cyan-400 underline">Anthropic Console</a>.';
    } else if (currentKey === 'ollama') {
      provKeyHelp.innerText = 'Pastikan server Ollama berjalan di localhost:11434 (100% offline air-gapped).';
    } else {
      provKeyHelp.innerText = 'Mode Mock Deterministic bawaan (offline tanpa koneksi luar).';
    }
  }
}

function renderProviderStatusCards(providers, active) {
  const container = document.getElementById('ai-providers-overview');
  if (!container) return;
  container.innerHTML = '';

  Object.entries(providers).forEach(([key, info]) => {
    const isActive = key === active;
    const card = document.createElement('div');
    card.className = `clay-card p-4 space-y-2 border ${isActive ? 'border-cyan-400/60 ring-2 ring-cyan-500/20' : 'border-slate-800'}`;
    card.innerHTML = `
      <div class="flex items-center justify-between">
        <span class="font-bold text-xs text-white">${info.name}</span>
        ${isActive ? '<span class="clay-pill bg-cyan-500/20 text-cyan-300 text-[9px]">AKTIF</span>' : ''}
      </div>
      <div class="text-[11px] text-slate-400 font-mono">Model: <span class="text-slate-200">${info.model}</span></div>
      <div class="text-[10px] text-slate-400 flex items-center gap-1.5">
        <span class="w-2 h-2 rounded-full ${info.configured ? 'bg-emerald-400' : 'bg-amber-400'}"></span>
        <span>Key: ${info.masked_key}</span>
      </div>
    `;
    container.appendChild(card);
  });
}

async function saveAISettings() {
  playClick();
  const selectProv = document.getElementById('select-ai-provider');
  const selectModel = document.getElementById('select-ai-model');
  const keyInput = document.getElementById('input-ai-api-key');
  const statusMsg = document.getElementById('ai-settings-status-msg');

  if (!selectProv) return;
  const payload = {
    provider: selectProv.value,
    model: selectModel?.value,
    api_key: keyInput?.value?.trim() || null,
    save_to_env: true
  };

  try {
    const res = await fetch('/api/settings/ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    playSuccessChime();
    if (statusMsg) {
      statusMsg.className = "text-xs font-semibold text-emerald-400";
      statusMsg.innerText = "✓ Pengaturan AI & API Key berhasil disimpan dan aktif!";
      setTimeout(() => { statusMsg.innerText = ''; }, 4000);
    }
    loadAISettings();
  } catch (err) {
    if (statusMsg) {
      statusMsg.className = "text-xs font-semibold text-red-400";
      statusMsg.innerText = "Gagal menyimpan pengaturan: " + err;
    }
  }
}

async function testCurrentAIConnection() {
  playClick();
  const selectProv = document.getElementById('select-ai-provider');
  const selectModel = document.getElementById('select-ai-model');
  const keyInput = document.getElementById('input-ai-api-key');
  const statusMsg = document.getElementById('ai-settings-status-msg');

  if (!selectProv) return;
  if (statusMsg) {
    statusMsg.className = "text-xs font-semibold text-cyan-400 animate-pulse";
    statusMsg.innerText = "Menguji koneksi ke provider AI...";
  }

  try {
    const res = await fetch('/api/settings/ai/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: selectProv.value,
        model: selectModel?.value,
        api_key: keyInput?.value?.trim() || null
      })
    });
    const data = await res.json();
    if (data.success) {
      playSuccessChime();
      if (statusMsg) {
        statusMsg.className = "text-xs font-semibold text-emerald-400";
        statusMsg.innerText = "✓ " + data.message;
      }
    } else {
      playAlarm();
      if (statusMsg) {
        statusMsg.className = "text-xs font-semibold text-red-400";
        statusMsg.innerText = "✗ " + data.message;
      }
    }
  } catch (err) {
    if (statusMsg) {
      statusMsg.className = "text-xs font-semibold text-red-400";
      statusMsg.innerText = "Error: " + err;
    }
  }
}

// -------------------------------------------------------------
// Threat Intelligence (MalwareBazaar & vx-underground) Controls
// -------------------------------------------------------------
async function loadThreatIntelStats() {
  try {
    const res = await fetch('/api/intel/stats');
    if (!res.ok) return;
    const stats = await res.json();

    const totalEl = document.getElementById('intel-total-hashes');
    const badEl = document.getElementById('intel-bad-hashes');
    const goodEl = document.getElementById('intel-good-hashes');
    const yaraEl = document.getElementById('intel-yara-rules');
    const famEl = document.getElementById('intel-families-list');
    const mbStatus = document.getElementById('mb-key-status');

    if (totalEl) totalEl.innerText = Number(stats.total_hashes || 0).toLocaleString();
    if (badEl) badEl.innerText = Number(stats.malicious_hashes || 0).toLocaleString();
    if (goodEl) goodEl.innerText = Number(stats.benign_hashes || 0).toLocaleString();
    if (yaraEl) yaraEl.innerText = (stats.yara_rules_count || 0) + ' Rule';

    if (famEl && stats.yara_families) {
      famEl.innerHTML = '';
      stats.yara_families.forEach(f => {
        const badge = document.createElement('span');
        badge.className = 'clay-pill bg-purple-500/20 text-purple-300 text-[10px] font-mono border border-purple-500/30';
        badge.innerText = f;
        famEl.appendChild(badge);
      });
    }

    if (mbStatus) {
      mbStatus.innerHTML = stats.malwarebazaar_configured
        ? '<span class="text-emerald-400 font-bold">✓ Auth-Key MalwareBazaar Terkonfigurasi</span>'
        : '<span class="text-amber-400 font-medium">⚠️ Auth-Key belum diisi (Query API dibatasi)</span>';
    }
  } catch (err) {
    console.debug('Failed loading intel stats:', err);
  }
}

async function syncThreatIntel() {
  playClick();
  const btn = document.getElementById('btn-sync-intel');
  if (btn) {
    btn.disabled = true;
    btn.innerText = '⏳ Mengunduh Intelijen...';
  }
  try {
    const res = await fetch('/api/intel/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tag: 'usb', limit: 100 })
    });
    const data = await res.json();
    playSuccessChime();
    alert(`Sinkronisasi Selesai!\nSampel Ditemukan: ${data.samples_fetched}\nHash Dimasukkan ke DB: ${data.hashes_inserted}`);
    loadThreatIntelStats();
  } catch (err) {
    playAlarm();
    alert('Gagal sinkronisasi intelijen: ' + err);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = '🔄 Sinkronisasi Intelijen';
    }
  }
}

async function seedThreatFeeds() {
  playClick();
  try {
    const res = await fetch('/api/intel/seed', { method: 'POST' });
    const data = await res.json();
    playSuccessChime();
    alert(`Berhasil memuat signature bawaan vx-underground!\nJumlah hash dimuat: ${data.seeded_count}`);
    loadThreatIntelStats();
  } catch (err) {
    playAlarm();
    alert('Gagal memuat signature bawaan: ' + err);
  }
}

async function saveMalwareBazaarKey() {
  playClick();
  const keyInput = document.getElementById('input-mb-api-key');
  const keyVal = keyInput?.value?.trim();
  if (!keyVal) {
    alert('Silakan masukkan MalwareBazaar Auth-Key!');
    return;
  }
  try {
    const currentProv = document.getElementById('select-ai-provider')?.value || 'gemini';
    const res = await fetch('/api/settings/ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: currentProv,
        malwarebazaar_key: keyVal,
        save_to_env: true
      })
    });
    if (res.ok) {
      playSuccessChime();
      alert('MalwareBazaar Auth-Key berhasil disimpan!');
      if (keyInput) keyInput.value = '';
      loadThreatIntelStats();
    }
  } catch (err) {
    playAlarm();
    alert('Gagal menyimpan key: ' + err);
  }
}

// Initialize Polling loop (Fast 1.2s reactive loop)
setInterval(checkDevices, 1200);
checkDevices();
loadThreatIntelStats();

