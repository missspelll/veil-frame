const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

const unicode_lower = {
  a: '𝐚',
  b: '𝖻',
  c: '𝖼',
  d: '𝖽',
  e: '𝐞',
  f: '𝖿',
  g: '𝗀',
  h: '𝗁',
  i: '𝐢',
  j: '𝗃',
  k: '𝗄',
  l: '𝗅',
  m: '𝗆',
  n: '𝗇',
  o: '𝐨',
  p: '𝗉',
  q: '𝗊',
  r: '𝗋',
  s: '𝗌',
  t: '𝗍',
  u: '𝐮',
  v: '𝗏',
  w: '𝗐',
  x: '𝗑',
  y: '𝗒',
  z: '𝗓',
};

function stylizeUi(text) {
  return String(text ?? '')
    .toLowerCase()
    .replace(/[a-z]/g, (ch) => unicode_lower[ch] || ch);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatTimer(seconds) {
  const mins = Math.floor(seconds / 60).toString().padStart(2, '0');
  const secs = Math.floor(seconds % 60).toString().padStart(2, '0');
  return `${mins}:${secs}`;
}

function startTimer(el, prefix) {
  const started = Date.now();
  el.textContent = `${prefix} · 00:00`;
  const id = setInterval(() => {
    const elapsed = (Date.now() - started) / 1000;
    el.textContent = `${prefix} · ${formatTimer(elapsed)}`;
  }, 1000);
  return () => {
    clearInterval(id);
    const elapsed = (Date.now() - started) / 1000;
    return formatTimer(elapsed);
  };
}

async function readJson(res) {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { error: text.slice(0, 200) };
  }
}

function validateImage(file) {
  if (!file) return stylizeUi('choose an image first.');
  if (!['image/png', 'image/jpeg'].includes(file.type) && !/\.(png|jpe?g)$/i.test(file.name || '')) {
    return stylizeUi('image must be png or jpeg.');
  }
  if (file.size > MAX_IMAGE_BYTES) return stylizeUi('image exceeds 8mb limit.');
  return '';
}

const encodeForm = document.getElementById('lite-encode-form');
const encodeMethod = document.getElementById('lite-encode-method');
const simplePanel = document.getElementById('lite-simple-panel');
const advancedPanel = document.getElementById('lite-advanced-panel');
const payloadText = document.getElementById('lite-text');
const payloadFile = document.getElementById('lite-payload-file');
const encodeOutput = document.getElementById('lite-encode-output');

const decodeForm = document.getElementById('lite-decode-form');
const decodeOutput = document.getElementById('lite-decode-output');
const decodeTimer = document.getElementById('lite-analysis-timer');
const toolStatus = document.getElementById('lite-tool-status');

function syncEncodeMethod() {
  const advanced = encodeMethod.value === 'advanced_lsb';
  simplePanel.classList.toggle('hidden', advanced);
  advancedPanel.classList.toggle('hidden', !advanced);

  const jpeg = encodeForm.querySelector('input[name="outputFormat"][value="jpeg"]');
  const png = encodeForm.querySelector('input[name="outputFormat"][value="png"]');
  if (advanced) {
    png.checked = true;
    jpeg.disabled = true;
  } else {
    jpeg.disabled = false;
  }
}

function syncSimplePayloadMode() {
  const mode = encodeForm.querySelector('input[name="payloadMode"]:checked')?.value || 'text';
  const isFile = mode === 'file';
  payloadText.classList.toggle('hidden', isFile);
  payloadFile.classList.toggle('hidden', !isFile);
  payloadText.disabled = isFile;
  payloadFile.disabled = !isFile;
}

encodeMethod.addEventListener('change', syncEncodeMethod);
encodeForm.querySelectorAll('input[name="payloadMode"]').forEach((el) => {
  el.addEventListener('change', syncSimplePayloadMode);
});

syncEncodeMethod();
syncSimplePayloadMode();

encodeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const carrier = document.getElementById('lite-carrier-image').files?.[0];
  const error = validateImage(carrier);
  if (error) {
    encodeOutput.innerHTML = `<div class="result-card"><pre>${escapeHtml(error)}</pre></div>`;
    return;
  }

  const method = encodeMethod.value;
  const fd = new FormData(encodeForm);
  fd.set('encodeMethod', method);

  if (method === 'advanced_lsb') {
    const channels = {};
    document.querySelectorAll('#lite-channel-grid .channel').forEach((node) => {
      const ch = node.dataset.channel;
      const enabled = node.querySelector('.enabled').checked;
      const text = node.querySelector('.text').value || '';
      const file = node.querySelector('.file').files?.[0] || null;
      const type = file ? 'file' : 'text';
      channels[ch] = { enabled, type, text };
      if (file) {
        fd.append(`file_${ch}`, file);
      }
    });
    fd.set('channels', JSON.stringify(channels));
  } else {
    const mode = encodeForm.querySelector('input[name="payloadMode"]:checked')?.value || 'text';
    if (mode === 'text' && !payloadText.value.trim()) {
      encodeOutput.innerHTML = `<div class="result-card"><pre>${escapeHtml(stylizeUi('enter a text payload first.'))}</pre></div>`;
      return;
    }
    if (mode === 'file' && !(payloadFile.files && payloadFile.files[0])) {
      encodeOutput.innerHTML = `<div class="result-card"><pre>${escapeHtml(stylizeUi('choose a payload file first.'))}</pre></div>`;
      return;
    }
    fd.set('mode', mode === 'file' ? 'zlib' : 'text');
  }

  encodeOutput.innerHTML = `<div class="result-card"><pre>${escapeHtml(stylizeUi('encoding…'))}</pre></div>`;
  try {
    const res = await fetch('/api/lite/encode', { method: 'POST', body: fd });
    const data = await readJson(res);
    if (!res.ok || data.error) throw new Error(data.error || `server error (${res.status})`);
    encodeOutput.innerHTML = `
      <div class="result-grid">
        <div class="result-card">
          <h3>${escapeHtml(stylizeUi('encoded image'))}</h3>
          <img src="${data.data_url}" alt="encoded" style="width:100%;border-radius:8px;border:1px solid rgba(255,255,255,.12)">
          <a class="download-link" href="${data.data_url}" download="${escapeHtml(data.filename)}">${escapeHtml(stylizeUi(`download ${data.filename}`))}</a>
        </div>
      </div>
    `;
  } catch (err) {
    encodeOutput.innerHTML = `<div class="result-card"><pre>${escapeHtml(stylizeUi(err.message || String(err)))}</pre></div>`;
  }
});

function payloadHtml(result) {
  if (!result || typeof result !== 'object') return `<pre>${escapeHtml(stylizeUi('no result'))}</pre>`;

  const sections = [];
  if (typeof result.output === 'string' && result.output.trim()) {
    sections.push(`<pre>${escapeHtml(result.output)}</pre>`);
  }

  if (result.decoded_text && typeof result.decoded_text === 'object') {
    const textRows = Object.entries(result.decoded_text)
      .filter(([, value]) => value)
      .map(([key, value]) => `${key}:\n${value}`);
    if (textRows.length) sections.push(`<pre>${escapeHtml(textRows.join('\n\n'))}</pre>`);
  }

  if (Array.isArray(result.matches) && result.matches.length) {
    const preview = result.matches
      .map((item) => `${item.plane || 'plane'} (${item.strategy || 'mode'}):\n${item.preview || ''}`)
      .join('\n\n');
    sections.push(`<pre>${escapeHtml(preview)}</pre>`);
  }

  if (result.details && typeof result.details === 'object') {
    const textChannels = result.details.text_channels;
    if (textChannels && typeof textChannels === 'object') {
      const joined = Object.entries(textChannels)
        .map(([ch, val]) => `${ch}:\n${val.text_preview || ''}`)
        .join('\n\n');
      if (joined.trim()) sections.push(`<pre>${escapeHtml(joined)}</pre>`);
    }

    const files = result.details.file_payloads;
    if (Array.isArray(files) && files.length) {
      const joined = files.map((item) => `${item.channel}:\n${item.preview || ''}`).join('\n\n');
      if (joined.trim()) sections.push(`<pre>${escapeHtml(joined)}</pre>`);
    }
  }

  if (!sections.length) {
    const fallback = result.reason || result.error || result.summary || stylizeUi('no payload detected');
    sections.push(`<pre>${escapeHtml(fallback)}</pre>`);
  }

  return sections.join('');
}

function renderLiteDecode(data) {
  const results = data.results || {};
  const order = [
    'simple_rgb',
    'red_plane',
    'green_plane',
    'blue_plane',
    'alpha_plane',
    'simple_lsb',
    'simple_zlib',
    'advanced_lsb',
  ];

  const cards = order
    .filter((key) => results[key])
    .map((key) => {
      const result = results[key];
      const status = escapeHtml(stylizeUi(result.status || 'unknown'));
      return `
        <div class="result-card">
          <h3>${escapeHtml(stylizeUi(key))} · ${status}</h3>
          ${payloadHtml(result)}
        </div>
      `;
    })
    .join('');

  decodeOutput.innerHTML = `<div class="result-grid">${cards || `<div class="result-card"><pre>${escapeHtml(stylizeUi('no results'))}</pre></div>`}</div>`;
}

decodeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const analyze = document.getElementById('lite-analyze-image').files?.[0];
  const error = validateImage(analyze);
  if (error) {
    decodeOutput.innerHTML = `<div class="result-card"><pre>${escapeHtml(error)}</pre></div>`;
    return;
  }

  const fd = new FormData(decodeForm);
  const stop = startTimer(decodeTimer, stylizeUi('status: running'));
  decodeOutput.innerHTML = `<div class="result-card"><pre>${escapeHtml(stylizeUi('decoding…'))}</pre></div>`;

  try {
    const res = await fetch('/api/lite/decode', { method: 'POST', body: fd });
    const data = await readJson(res);
    if (!res.ok || data.error) throw new Error(data.error || `server error (${res.status})`);
    renderLiteDecode(data);
    const elapsed = stop();
    decodeTimer.textContent = `${stylizeUi('status: complete')} · ${elapsed}`;
  } catch (err) {
    const elapsed = stop();
    decodeTimer.textContent = `${stylizeUi('status: failed')} · ${elapsed}`;
    decodeOutput.innerHTML = `<div class="result-card"><pre>${escapeHtml(stylizeUi(err.message || String(err)))}</pre></div>`;
  }
});

async function loadLiteTools() {
  try {
    const res = await fetch('/api/lite/tools');
    const data = await readJson(res);
    const tools = data.tools || {};
    const html = Object.entries(tools)
      .map(([name, info]) => `<div class="tool-pill">${escapeHtml(stylizeUi(name))} · ${escapeHtml(stylizeUi(info.available ? 'ok' : 'missing'))}</div>`)
      .join('');
    toolStatus.innerHTML = html || `<div class="tool-pill">${escapeHtml(stylizeUi('no tools'))}</div>`;
  } catch {
    toolStatus.innerHTML = `<div class="tool-pill">${escapeHtml(stylizeUi('tooling unavailable'))}</div>`;
  }
}

loadLiteTools();
