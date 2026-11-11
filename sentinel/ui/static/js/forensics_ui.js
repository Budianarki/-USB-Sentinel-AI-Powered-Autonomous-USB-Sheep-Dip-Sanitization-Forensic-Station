/**
 * Forensic analysis viewer UI: Hex dumper, Shannon entropy visualizer, and string inspector.
 */

function renderForensicList(files) {
  const container = document.getElementById('forensic-file-list');
  if (!container) return;
  container.innerHTML = '';
  files.forEach((f, idx) => {
    const btn = document.createElement('button');
    btn.className = "w-full text-left p-2.5 rounded-xl clay-card hover:border-cyan-500/50 transition-all flex items-center justify-between text-xs";
    btn.innerHTML = `
      <span class="truncate font-mono">${f.name}</span>
      <span class="text-[10px] text-slate-400">${f.size_bytes}B</span>
    `;
    btn.onclick = () => loadForensicsDetail(f.abs_path, f.name);
    container.appendChild(btn);
    if (idx === 0) loadForensicsDetail(f.abs_path, f.name);
  });
}

async function loadForensicsDetail(absPath, name) {
  playClick();
  const nameEl = document.getElementById('forensic-active-name');
  if (nameEl) nameEl.innerText = name;

  try {
    const res = await fetch(`/api/forensics?path=${encodeURIComponent(absPath)}`);
    const data = await res.json();

    const sizeEl = document.getElementById('forensic-active-size');
    const entEl = document.getElementById('forensic-total-entropy');
    if (sizeEl) sizeEl.innerText = `${data.size_bytes} Bytes`;
    if (entEl) entEl.innerText = `Entropi Total: ${data.total_entropy}`;

    // Hex view
    const hexLines = (data.hex_lines || []).map(l => `${l.offset}  ${l.hex}  |${l.ascii}|`).join('\n');
    const hexViewEl = document.getElementById('forensic-hex-view');
    if (hexViewEl) hexViewEl.innerText = hexLines || "Tidak ada data hex.";

    // Entropy bars
    const barsBox = document.getElementById('entropy-bars-container');
    if (barsBox) {
      barsBox.innerHTML = '';
      (data.entropy_blocks || []).forEach(b => {
        const bar = document.createElement('div');
        const pct = Math.min(100, Math.round((b / 8.0) * 100));
        bar.className = "flex-1 rounded-t " + (b > 6.5 ? "bg-red-400" : (b > 4.5 ? "bg-amber-400" : "bg-cyan-400"));
        bar.style.height = `${pct}%`;
        bar.title = `Block Entropy: ${b}`;
        barsBox.appendChild(bar);
      });
    }

    // Strings
    const strBox = document.getElementById('forensic-strings-box');
    if (strBox) {
      strBox.innerHTML = '';
      const allStrings = [...(data.suspicious_tokens || []), ...(data.strings || [])];
      allStrings.slice(0, 30).forEach(s => {
        const span = document.createElement('span');
        span.className = "clay-pill bg-slate-800 text-slate-300 font-mono text-[10px]";
        span.innerText = s;
        strBox.appendChild(span);
      });
    }

  } catch (e) {
    console.debug("Forensics error:", e);
  }
}

// Modal Forensic Inspector (Pop-up)
async function openForensicsModal(absPath, name) {
  playTone(800, 0.08);
  const modal = document.getElementById('modal-forensic');
  if (modal) modal.classList.remove('hidden');

  const titleEl = document.getElementById('modal-file-title');
  const subEl = document.getElementById('modal-file-subtitle');
  if (titleEl) titleEl.innerText = name;
  if (subEl) subEl.innerText = absPath;

  try {
    const res = await fetch(`/api/forensics?path=${encodeURIComponent(absPath)}`);
    const data = await res.json();

    const entVal = document.getElementById('modal-entropy-val');
    if (entVal) entVal.innerText = `Total: ${data.total_entropy} (Shannon)`;

    // Hex
    const hexLines = (data.hex_lines || []).map(l => `${l.offset}  ${l.hex}  |${l.ascii}|`).join('\n');
    const hexContent = document.getElementById('modal-hex-content');
    if (hexContent) hexContent.innerText = hexLines || "Tidak ada data biner.";

    // Entropy bars
    const barsBox = document.getElementById('modal-entropy-bars');
    if (barsBox) {
      barsBox.innerHTML = '';
      (data.entropy_blocks || []).forEach(b => {
        const bar = document.createElement('div');
        const pct = Math.min(100, Math.round((b / 8.0) * 100));
        bar.className = "flex-1 rounded-t " + (b > 6.5 ? "bg-red-400" : "bg-cyan-400");
        bar.style.height = `${pct}%`;
        bar.title = `Entropy: ${b}`;
        barsBox.appendChild(bar);
      });
    }

    // Strings
    const strBox = document.getElementById('modal-strings-content');
    if (strBox) {
      strBox.innerHTML = '';
      (data.strings || []).slice(0, 20).forEach(s => {
        const sp = document.createElement('span');
        sp.className = "clay-pill bg-slate-800 text-slate-300 font-mono text-[10px]";
        sp.innerText = s;
        strBox.appendChild(sp);
      });
    }

  } catch (e) {
    alert("Gagal load forensik: " + e);
  }
}

function closeForensicModal() {
  playClick();
  const modal = document.getElementById('modal-forensic');
  if (modal) modal.classList.add('hidden');
}

