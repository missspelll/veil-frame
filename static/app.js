const panels = {
  encode: document.getElementById('encode-panel'),
  decode: document.getElementById('decode-panel'),
};

const modeButtons = document.querySelectorAll('.mode-btn');
const toolStatusEl = document.getElementById('tool-status-list');
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const ALLOWED_IMAGE_TYPES = new Set(['image/png', 'image/jpeg']);
const ALLOWED_IMAGE_EXTS = ['.png', '.jpg', '.jpeg'];

const decodeOptionPriority = [
  'auto_detect',
  'lsb',
  'pvd',
  'dct',
  'f5',
  'spread_spectrum',
  'palette',
  'chroma',
  'png_chunks',
];

const restOrder = [
  'advanced_lsb',
  'simple_lsb',
  'simple_zlib',
  'stegg',
  'zero_width',
  'invisible_unicode',
  'randomizer_decode',
  'payload_unwrap',
  'xor_flag_sweep',
  'pre_analysis',
  'binwalk',
  'foremost',
  'exiftool',
  'steghide',
  'outguess',
  'zsteg',
  'decomposer',
  'plane_carver',
  'entropy_analyzer',
  'jpeg_qtable_analyzer',
  'statistical_steg',
  'identify',
  'convert',
  'jpeginfo',
  'jpegtran',
  'cjpeg',
  'djpeg',
  'jpegsnoop',
  'jhead',
  'exiv2',
  'exifprobe',
  'pngcheck',
  'optipng',
  'pngcrush',
  'pngtools',
  'stegdetect',
  'jsteg',
  'stegbreak',
  'stegseek',
  'stegcracker',
  'fcrackzip',
  'bulk_extractor',
  'scalpel',
  'testdisk',
  'photorec',
  'stegoveritas',
  'zbarimg',
  'qrencode',
  'tesseract',
  'ffprobe',
  'ffmpeg',
  'mediainfo',
  'sox',
  'pdfinfo',
  'pdftotext',
  'pdfimages',
  'qpdf',
  'radare2',
  'rizin',
  'hexyl',
  'bvi',
  'xxd',
  'rg',
  'tshark',
  'wireshark',
  'sleuthkit',
  'volatility',
  'stegsolve',
  'stegosuite',
  'stegpy',
  'stegolsb',
  'lsbsteg',
  'stegano_lsb',
  'stegano_lsb_set',
  'stegano_red',
  'cloackedpixel',
  'cloackedpixel_analyse',
  'jphide',
  'jphs',
  'jpseek',
  'stegsnow',
  'hideme',
  'mp3stego_encode',
  'mp3stego_decode',
  'openpuff',
  'deepsound',
  'sonic_visualiser',
  'stegify',
  'openstego',
];

const profileState = {
  profiles: [],
  byId: {},
  defaultProfile: 'balanced',
  tools: {},
  analyzers: [],
  analyzerById: {},
  defaultSelectedTools: [],
  selectedToolsByProfile: {},
};

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

function hasSupportedExtension(name) {
  const lower = (name || '').toLowerCase();
  return ALLOWED_IMAGE_EXTS.some((ext) => lower.endsWith(ext));
}

function isSupportedImage(file) {
  if (!file) return false;
  if (file.type) return ALLOWED_IMAGE_TYPES.has(file.type);
  return hasSupportedExtension(file.name);
}

function validateImageFile(file) {
  if (!file) return stylizeUi('please choose an image to upload.');
  if (!isSupportedImage(file)) return stylizeUi('unsupported image type. please use png or jpg.');
  if (file.size > MAX_IMAGE_BYTES) return stylizeUi(`image too large. try under ${(MAX_IMAGE_BYTES / (1024 * 1024)).toFixed(1)} mb.`);
  return null;
}

function formatDurationMs(ms) {
  const totalSec = Math.max(0, Math.round(Number(ms || 0) / 1000));
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  if (!mins) return `${secs}s`;
  return `${mins}m ${secs.toString().padStart(2, '0')}s`;
}

function formatClock(seconds) {
  const mins = Math.floor(seconds / 60).toString().padStart(2, '0');
  const secs = Math.floor(seconds % 60).toString().padStart(2, '0');
  return `${mins}:${secs}`;
}

async function readResponse(res) {
  const text = await res.text();
  if (!text) return { data: null, text: '' };
  try {
    return { data: JSON.parse(text), text };
  } catch (_) {
    return { data: null, text };
  }
}

function responseMessage(res, data, text) {
  const status = `${res.status}${res.statusText ? ` ${res.statusText}` : ''}`;
  if (data && data.error) return stylizeUi(`server response (${status}): ${data.error}`);
  if (text) return stylizeUi(`server response (${status}): ${text.replace(/\s+/g, ' ').slice(0, 180)}`);
  return stylizeUi(`server response (${status})`);
}

function showPanel(targetId, persist = true) {
  if (persist && targetId) localStorage.setItem('activePanel', targetId);
  modeButtons.forEach((btn) => btn.classList.remove('active'));

  Object.entries(panels).forEach(([key, panel]) => {
    if (!panel) return;
    const id = `${key}-panel`;
    const active = id === targetId;
    panel.classList.toggle('active', active);
    const tab = document.querySelector(`.mode-btn[data-target="${id}"]`);
    if (tab) tab.classList.toggle('active', active);
    if (active && id === 'decode-panel') {
      loadProfilesAndTools();
    }
  });
}

modeButtons.forEach((btn) => {
  btn.addEventListener('click', () => showPanel(btn.dataset.target, true));
});

const savedPanel = localStorage.getItem('activePanel');
const initialPanel = savedPanel === 'decode-panel' || savedPanel === 'encode-panel' ? savedPanel : 'encode-panel';
showPanel(initialPanel, false);

const encodeMethodSelect = document.getElementById('encode-method');
const simplePlaneField = document.getElementById('simple-plane-field');
const advancedGrid = document.getElementById('advanced-grid');
const jpegFormatRadio = document.querySelector('input[name="outputFormat"][value="jpeg"]');
const pngFormatRadio = document.querySelector('input[name="outputFormat"][value="png"]');
const methodPanels = document.querySelectorAll('[data-encode-method]');
const methodOptionsField = document.getElementById('encode-method-options');
const payloadModeRadios = document.querySelectorAll('input[name="payloadMode"]');
const payloadTextPanel = document.getElementById('payload-text-panel');
const payloadFilePanel = document.getElementById('payload-file-panel');
const payloadFileInput = document.getElementById('payload-file-input');
const payloadFileName = document.getElementById('payload-file-name');
const payloadTextArea = document.querySelector('#payload-text-panel textarea[name="text"]');

function syncOutputFormatForMethod(method) {
  if (!jpegFormatRadio || !pngFormatRadio) return;
  let force = '';
  if (['advanced_lsb', 'palette', 'png_chunks'].includes(method)) force = 'png';
  if (['f5', 'dct'].includes(method)) force = 'jpeg';

  if (!force) {
    jpegFormatRadio.disabled = false;
    pngFormatRadio.disabled = false;
    return;
  }
  if (force === 'png') {
    pngFormatRadio.checked = true;
    pngFormatRadio.disabled = false;
    jpegFormatRadio.disabled = true;
  } else {
    jpegFormatRadio.checked = true;
    jpegFormatRadio.disabled = false;
    pngFormatRadio.disabled = true;
  }
}

function getPayloadMode() {
  const selected = document.querySelector('input[name="payloadMode"]:checked');
  return selected ? selected.value : 'text';
}

function setPayloadModeUI() {
  const mode = getPayloadMode();
  const useFile = mode === 'file';
  if (payloadTextPanel) payloadTextPanel.classList.toggle('hidden', useFile);
  if (payloadFilePanel) payloadFilePanel.classList.toggle('hidden', !useFile);
  if (payloadTextArea) payloadTextArea.disabled = useFile;
  if (payloadFileInput) payloadFileInput.disabled = !useFile;
}

function setEncodeMethodUI() {
  const method = encodeMethodSelect ? encodeMethodSelect.value : 'simple_lsb';
  const advanced = method === 'advanced_lsb';
  if (simplePlaneField) simplePlaneField.style.display = advanced ? 'none' : 'flex';
  if (advancedGrid) advancedGrid.style.display = advanced ? 'grid' : 'none';

  let hasActivePanel = false;
  methodPanels.forEach((panel) => {
    const active = panel.dataset.encodeMethod === method;
    panel.classList.toggle('hidden', !active);
    panel.querySelectorAll('input, select, textarea').forEach((el) => {
      el.disabled = !active;
    });
    if (active) hasActivePanel = true;
  });

  if (methodOptionsField) methodOptionsField.style.display = hasActivePanel ? 'flex' : 'none';
  syncOutputFormatForMethod(method);
  setPayloadModeUI();
  localStorage.setItem('encodeMethod', method);
}

if (encodeMethodSelect) {
  const savedMethod = localStorage.getItem('encodeMethod');
  const legacyMode = localStorage.getItem('encodeMode');
  if (savedMethod) encodeMethodSelect.value = savedMethod;
  else if (legacyMode === 'advanced') encodeMethodSelect.value = 'advanced_lsb';
  encodeMethodSelect.addEventListener('change', setEncodeMethodUI);
}
payloadModeRadios.forEach((radio) => radio.addEventListener('change', setPayloadModeUI));
setEncodeMethodUI();

const carrierInput = document.getElementById('carrier-image');
const carrierFilename = document.getElementById('carrier-filename');
const analyzeInput = document.getElementById('analyze-image');
const analyzeFilename = document.getElementById('analyze-filename');

function bindFileLabel(inputEl, labelEl, emptyLabel) {
  if (!inputEl || !labelEl) return;
  const update = () => {
    const file = inputEl.files && inputEl.files[0] ? inputEl.files[0] : null;
    const name = file ? `${file.name} (${(file.size / (1024 * 1024)).toFixed(1)} mb)` : emptyLabel;
    labelEl.textContent = name;
  };
  inputEl.addEventListener('change', update);
  update();
}

bindFileLabel(carrierInput, carrierFilename, 'no photo chosen');
bindFileLabel(analyzeInput, analyzeFilename, 'no photo chosen');
bindFileLabel(payloadFileInput, payloadFileName, 'no file');

function toggleChannelBodies() {
  document.querySelectorAll('#advanced-grid .channel-card').forEach((card) => {
    const enabledToggle = card.querySelector('.ch-enabled');
    if (!enabledToggle) return;
    card.classList.toggle('channel-collapsed', !enabledToggle.checked);
  });
}

function saveChannelState() {
  const state = {};
  document.querySelectorAll('#advanced-grid .channel-card').forEach((card) => {
    const ch = card.dataset.channel;
    const enabledToggle = card.querySelector('.ch-enabled');
    const textField = card.querySelector('.ch-text');
    if (!enabledToggle || !textField) return;
    state[ch] = { enabled: enabledToggle.checked, text: textField.value };
  });
  localStorage.setItem('channelsState', JSON.stringify(state));
}

function loadChannelState() {
  const saved = localStorage.getItem('channelsState');
  if (!saved) return;
  try {
    const state = JSON.parse(saved);
    document.querySelectorAll('#advanced-grid .channel-card').forEach((card) => {
      const ch = card.dataset.channel;
      const cfg = state[ch];
      if (!cfg) return;
      const enabledToggle = card.querySelector('.ch-enabled');
      const textField = card.querySelector('.ch-text');
      if (enabledToggle) enabledToggle.checked = !!cfg.enabled;
      if (textField) textField.value = cfg.text || '';
    });
  } catch (_) {
    /* ignore */
  }
}

document.querySelectorAll('#advanced-grid .channel-card').forEach((card) => {
  const enabled = card.querySelector('.ch-enabled');
  const textArea = card.querySelector('.ch-text');
  const fileInput = card.querySelector('.ch-file');
  if (enabled) {
    enabled.addEventListener('change', () => {
      toggleChannelBodies();
      saveChannelState();
    });
  }
  if (textArea) textArea.addEventListener('input', saveChannelState);
  if (fileInput) {
    fileInput.addEventListener('change', () => {
      const nameEl = card.querySelector('.ch-file-name');
      const name = fileInput.files && fileInput.files[0] ? fileInput.files[0].name : 'no file';
      if (nameEl) nameEl.textContent = name;
      saveChannelState();
    });
    const nameEl = card.querySelector('.ch-file-name');
    const name = fileInput.files && fileInput.files[0] ? fileInput.files[0].name : 'no file';
    if (nameEl) nameEl.textContent = name;
  }
});

loadChannelState();
toggleChannelBodies();

const encodeForm = document.getElementById('encode-form');
const encodeOutput = document.getElementById('encode-output');

function renderEncodeResult(data) {
  encodeOutput.innerHTML = `
    <div class="result-grid">
      <div class="result-card">
        <h3>${escapeHtml(stylizeUi('encoded image'))}</h3>
        <img src="${data.data_url}" alt="encoded" style="width:100%;border-radius:10px;border:1px solid rgba(255,255,255,0.1);background:rgba(255,255,255,0.02);">
        <div class="downloads" style="margin-top:10px;">
          <a href="${data.data_url}" download="${escapeHtml(data.filename)}">${escapeHtml(stylizeUi(`download ${data.filename}`))}</a>
        </div>
      </div>
    </div>
  `;
}

if (encodeForm) {
  encodeForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const carrierFile = carrierInput && carrierInput.files ? carrierInput.files[0] : null;
    const carrierError = validateImageFile(carrierFile);
    if (carrierError) {
      encodeOutput.innerHTML = `<div class="status-line error">${escapeHtml(carrierError)}</div>`;
      return;
    }

    encodeOutput.innerHTML = `<div class="status-line">${escapeHtml(stylizeUi('encoding…'))}</div>`;

    const encodeMethod = encodeMethodSelect ? encodeMethodSelect.value : 'simple_lsb';
    const payloadMode = getPayloadMode();
    const payloadFile = payloadFileInput && payloadFileInput.files ? payloadFileInput.files[0] : null;
    const payloadText = payloadTextArea ? payloadTextArea.value.trim() : '';

    if (encodeMethod !== 'advanced_lsb') {
      if (payloadMode === 'file' && !payloadFile) {
        encodeOutput.innerHTML = `<div class="status-line error">${escapeHtml(stylizeUi('choose a payload file first.'))}</div>`;
        return;
      }
      if (payloadMode === 'text' && !payloadText) {
        encodeOutput.innerHTML = `<div class="status-line error">${escapeHtml(stylizeUi('enter a payload message first.'))}</div>`;
        return;
      }
    }

    const fd = new FormData(encodeForm);
    fd.set('encodeMethod', encodeMethod);

    try {
      if (encodeMethod === 'advanced_lsb') {
        const channels = {};
        document.querySelectorAll('#advanced-grid .channel-card').forEach((card) => {
          const ch = card.dataset.channel;
          const enabledToggle = card.querySelector('.ch-enabled');
          const textField = card.querySelector('.ch-text');
          const fileInput = card.querySelector('.ch-file');
          if (!enabledToggle || !textField) return;
          const enabled = enabledToggle.checked;
          const text = textField.value;
          const fileObj = fileInput && fileInput.files.length ? fileInput.files[0] : null;
          const type = fileObj ? 'file' : 'text';
          channels[ch] = { enabled, type, text };
          if (fileObj) fd.append(`file_${ch}`, fileObj);
        });
        fd.set('channels', JSON.stringify(channels));
      } else if (encodeMethod === 'simple_lsb') {
        fd.set('mode', payloadMode === 'file' ? 'zlib' : 'text');
      }

      const res = await fetch('/api/encode', { method: 'POST', body: fd });
      const { data, text } = await readResponse(res);
      if (!res.ok) throw new Error(responseMessage(res, data, text));
      if (!data) throw new Error(responseMessage(res, data, text));
      if (data.error) throw new Error(data.error);
      renderEncodeResult(data);
    } catch (err) {
      encodeOutput.innerHTML = `<div class="status-line error">${escapeHtml(stylizeUi(err.message || String(err)))}</div>`;
    }
  });
}

const decodeForm = document.getElementById('decode-form');
const decodeOutput = document.getElementById('decode-output');
const analysisProfileSelect = document.getElementById('analysis-profile');
const profileDescriptionEl = document.getElementById('profile-description');
const analysisEtaEl = document.getElementById('analysis-eta');
const analysisToolsEl = document.getElementById('analysis-active-tools');
const analysisTimerEl = document.getElementById('analysis-timer');
const analyzerGridEl = document.getElementById('analyzer-grid');
const selectedToolsInputEl = document.getElementById('selected-tools-input');
const selectAllToolsBtn = document.getElementById('select-all-tools');
const selectNoToolsBtn = document.getElementById('select-no-tools');
const selectProfileToolsBtn = document.getElementById('select-profile-tools');

const unicodeToggle = document.querySelector('input[name="unicodeSweep"]');
const unicodeOptions = document.getElementById('unicode-options');

function syncUnicodeOptions() {
  if (!unicodeOptions) return;
  const enabled = unicodeToggle && unicodeToggle.checked;
  unicodeOptions.classList.toggle('visible', !!enabled);
  unicodeOptions.querySelectorAll('input, select').forEach((el) => {
    el.disabled = !enabled;
  });
}
if (unicodeToggle) {
  unicodeToggle.addEventListener('change', syncUnicodeOptions);
  syncUnicodeOptions();
}

const advancedOptionDefaults = {
  quick:    { spread: false, binwalk: false, unicode: false, tier1: false, separators: false, aggressiveness: 'low' },
  balanced: { spread: false, binwalk: false, unicode: false, tier1: false, separators: false, aggressiveness: 'low' },
  deep:     { spread: true,  binwalk: true,  unicode: false, tier1: false, separators: false, aggressiveness: 'balanced' },
  forensic: { spread: true,  binwalk: true,  unicode: true,  tier1: true,  separators: true,  aggressiveness: 'high' },
};

function syncAdvancedOptions(profileId) {
  const defaults = advancedOptionDefaults[profileId] || advancedOptionDefaults.balanced;

  const spreadEl = document.querySelector('input[name="spreadSpectrum"]');
  const binwalkEl = document.querySelector('input[name="binwalkExtract"]');
  const tier1El = document.querySelector('input[name="unicodeTier1"]');
  const sepsEl = document.querySelector('input[name="unicodeSeparators"]');
  const aggrEl = document.querySelector('select[name="unicodeAggressiveness"]');

  if (spreadEl) spreadEl.checked = defaults.spread;
  if (binwalkEl) binwalkEl.checked = defaults.binwalk;
  if (unicodeToggle) unicodeToggle.checked = defaults.unicode;
  if (tier1El) tier1El.checked = defaults.tier1;
  if (sepsEl) sepsEl.checked = defaults.separators;
  if (aggrEl) aggrEl.value = defaults.aggressiveness;

  syncUnicodeOptions();
}

function startLiveTimer(prefix) {
  if (!analysisTimerEl) return () => '00:00';
  const started = Date.now();
  analysisTimerEl.textContent = `${prefix} · 00:00`;
  const timerId = setInterval(() => {
    const elapsedSec = (Date.now() - started) / 1000;
    analysisTimerEl.textContent = `${prefix} · ${formatClock(elapsedSec)}`;
  }, 1000);

  return (finalStatus = 'complete') => {
    clearInterval(timerId);
    const elapsedSec = (Date.now() - started) / 1000;
    analysisTimerEl.textContent = `${finalStatus} · ${formatClock(elapsedSec)}`;
    return elapsedSec;
  };
}

async function loadProfilesAndTools() {
  try {
    const [profileRes, toolsRes] = await Promise.all([
      fetch('/api/profiles'),
      fetch('/api/tools'),
    ]);
    const profileData = await profileRes.json();
    const toolsData = await toolsRes.json();

    const profiles = Array.isArray(profileData.profiles) ? profileData.profiles : [];
    profileState.defaultProfile = profileData.default_profile || 'balanced';
    profileState.profiles = profiles;
    profileState.byId = Object.fromEntries(profiles.map((row) => [row.id, row]));
    profileState.tools = toolsData.tools || {};
    profileState.analyzers = Array.isArray(profileData.analyzers) ? profileData.analyzers : [];
    profileState.analyzerById = Object.fromEntries(
      profileState.analyzers.map((row) => [row.id, row])
    );
    profileState.defaultSelectedTools = Array.isArray(profileData.default_selected_tools)
      ? profileData.default_selected_tools
      : [];

    if (analysisProfileSelect) {
      const saved = localStorage.getItem('analysisProfile') || profileState.defaultProfile;
      analysisProfileSelect.value = profileState.byId[saved] ? saved : profileState.defaultProfile;
    }

    const initialProfile = selectedProfileId();
    await loadAnalyzerCatalog(initialProfile);
    syncProfileUI();
    syncAdvancedOptions(initialProfile);
  } catch {
    if (toolStatusEl) toolStatusEl.innerHTML = `<div class="status-line">${stylizeUi('tool status unavailable')}</div>`;
    if (profileDescriptionEl) profileDescriptionEl.textContent = stylizeUi('unable to load analysis profiles.');
  }
}

function selectedProfileId() {
  if (!analysisProfileSelect) return profileState.defaultProfile;
  return analysisProfileSelect.value || profileState.defaultProfile;
}

function selectedToolsStorageKey(profileId) {
  return `selectedAnalyzers:${profileId}`;
}

function loadSelectedToolsForProfile(profileId) {
  if (profileState.selectedToolsByProfile[profileId]) {
    return new Set(profileState.selectedToolsByProfile[profileId]);
  }

  const allAnalyzerIds = new Set(
    profileState.analyzers.map((row) => row.id)
  );
  const profileIds = new Set(
    profileState.analyzers
      .filter((row) => row.enabled_in_profile)
      .map((row) => row.id)
  );
  const fallback = Array.isArray(profileState.defaultSelectedTools)
    ? profileState.defaultSelectedTools
    : Array.from(profileIds);

  const savedRaw = localStorage.getItem(selectedToolsStorageKey(profileId));
  if (!savedRaw) {
    const initial = fallback.filter((id) => profileIds.has(id));
    profileState.selectedToolsByProfile[profileId] = initial;
    return new Set(initial);
  }

  try {
    const parsed = JSON.parse(savedRaw);
    if (!Array.isArray(parsed)) throw new Error('invalid selection');
    const normalized = parsed.map((item) => String(item || '').toLowerCase()).filter((id) => allAnalyzerIds.has(id));
    profileState.selectedToolsByProfile[profileId] = normalized;
    return new Set(normalized);
  } catch {
    const initial = fallback.filter((id) => profileIds.has(id));
    profileState.selectedToolsByProfile[profileId] = initial;
    return new Set(initial);
  }
}

function persistSelectedToolsForProfile(profileId, selectedSet) {
  const values = Array.from(selectedSet).sort();
  profileState.selectedToolsByProfile[profileId] = values;
  localStorage.setItem(selectedToolsStorageKey(profileId), JSON.stringify(values));
  if (selectedToolsInputEl) {
    selectedToolsInputEl.value = JSON.stringify(values);
  }
}

function selectedAnalyzerIds(profileId) {
  return Array.from(loadSelectedToolsForProfile(profileId)).sort();
}

function renderAnalyzerSelector(profileId) {
  if (!analyzerGridEl) return;
  const selectedSet = loadSelectedToolsForProfile(profileId);

  const html = profileState.analyzers.map((tool) => {
    const id = String(tool.id || '').toLowerCase();
    const enabled = !!tool.enabled_in_profile;
    const checked = selectedSet.has(id);
    const offProfile = !enabled && checked;
    return `
      <label class="analyzer-pill ${enabled ? '' : checked ? 'off-profile' : 'unavailable'}">
        <input type="checkbox" class="analyzer-checkbox" value="${escapeHtml(id)}" ${checked ? 'checked' : ''}>
        <div class="analyzer-meta">
          <span class="analyzer-name">${escapeHtml(stylizeUi(tool.label || id))}${offProfile ? ' <span class="off-profile-badge">+</span>' : ''}</span>
          <span class="analyzer-eta">${escapeHtml(stylizeUi(`eta ${tool.eta_label || ''}`))}</span>
          <span class="analyzer-desc">${escapeHtml(stylizeUi(tool.description || ''))}</span>
        </div>
      </label>
    `;
  }).join('');

  analyzerGridEl.innerHTML = html || `<div class="status-line">${escapeHtml(stylizeUi('no analyzers for this profile'))}</div>`;
  persistSelectedToolsForProfile(profileId, selectedSet);
}

async function loadAnalyzerCatalog(profileId) {
  try {
    const res = await fetch(`/api/analyzers?profile=${encodeURIComponent(profileId)}`);
    const data = await res.json();
    profileState.analyzers = Array.isArray(data.analyzers) ? data.analyzers : [];
    profileState.analyzerById = Object.fromEntries(
      profileState.analyzers.map((row) => [row.id, row])
    );
    profileState.defaultSelectedTools = Array.isArray(data.default_selected_tools)
      ? data.default_selected_tools
      : [];
    renderAnalyzerSelector(profileId);
  } catch {
    profileState.analyzers = [];
    profileState.analyzerById = {};
    profileState.defaultSelectedTools = [];
    if (analyzerGridEl) {
      analyzerGridEl.innerHTML = `<div class="status-line">${escapeHtml(stylizeUi('unable to load analyzer catalog'))}</div>`;
    }
  }
}

if (analyzerGridEl) {
  analyzerGridEl.addEventListener('change', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) return;
    if (!target.classList.contains('analyzer-checkbox')) return;
    const profileId = selectedProfileId();
    const selected = new Set();
    analyzerGridEl.querySelectorAll('input.analyzer-checkbox').forEach((checkbox) => {
      if (!(checkbox instanceof HTMLInputElement)) return;
      if (!checkbox.checked) return;
      selected.add(String(checkbox.value || '').toLowerCase());
    });
    persistSelectedToolsForProfile(profileId, selected);
    syncProfileUI();
  });
}

if (selectAllToolsBtn) {
  selectAllToolsBtn.addEventListener('click', () => {
    const profileId = selectedProfileId();
    const all = new Set(
      profileState.analyzers
        .map((row) => String(row.id || '').toLowerCase())
    );
    persistSelectedToolsForProfile(profileId, all);
    renderAnalyzerSelector(profileId);
    syncProfileUI();
  });
}

if (selectNoToolsBtn) {
  selectNoToolsBtn.addEventListener('click', () => {
    const profileId = selectedProfileId();
    persistSelectedToolsForProfile(profileId, new Set());
    renderAnalyzerSelector(profileId);
    syncProfileUI();
  });
}

if (selectProfileToolsBtn) {
  selectProfileToolsBtn.addEventListener('click', () => {
    const profileId = selectedProfileId();
    const recommended = new Set(
      (profileState.defaultSelectedTools || []).map((item) => String(item || '').toLowerCase())
    );
    persistSelectedToolsForProfile(profileId, recommended);
    renderAnalyzerSelector(profileId);
    syncProfileUI();
  });
}

function toolMatchesAnalyzer(toolName) {
  const normalized = toolName.replace(/[-\s]/g, '_').toLowerCase();
  return profileState.analyzers.find(
    (a) => a.id === normalized || a.id === toolName.toLowerCase()
  );
}

function isToolAnalyzerSelected(toolName, profileId) {
  const selected = loadSelectedToolsForProfile(profileId);
  const analyzer = toolMatchesAnalyzer(toolName);
  return analyzer ? selected.has(analyzer.id) : false;
}

function toggleToolAnalyzer(toolName, checked) {
  const profileId = selectedProfileId();
  const analyzer = toolMatchesAnalyzer(toolName);
  if (!analyzer) return;
  const selected = loadSelectedToolsForProfile(profileId);
  if (checked) {
    selected.add(analyzer.id);
  } else {
    selected.delete(analyzer.id);
  }
  persistSelectedToolsForProfile(profileId, selected);
  renderAnalyzerSelector(profileId);
  // Update tool count chip without re-rendering tool pills (avoids loop)
  const profile = profileState.byId[profileId] || profileState.byId[profileState.defaultProfile];
  if (profile && analysisToolsEl) {
    const externalTools = Array.isArray(profile.external_tools) ? profile.external_tools : [];
    const internalTools = Array.isArray(profile.internal_tools) ? profile.internal_tools : [];
    const selectedCount = selectedAnalyzerIds(profileId).length;
    const available = externalTools.filter((name) => profileState.tools[name]?.available).length;
    const total = externalTools.length;
    if (!total) {
      analysisToolsEl.textContent = stylizeUi(`tools: ${selectedCount} selected · ${internalTools.length} internal`);
    } else {
      analysisToolsEl.textContent = stylizeUi(`tools: ${selectedCount} selected · ${available}/${total} external + ${internalTools.length} internal`);
    }
  }
}

function renderToolPills(profile) {
  if (!toolStatusEl) return;
  const externalTools = Array.isArray(profile?.external_tools) ? profile.external_tools : [];
  const internalTools = Array.isArray(profile?.internal_tools) ? profile.internal_tools : [];
  const profileId = profile.id || selectedProfileId();

  const externalHtml = externalTools.map((name) => {
    const info = profileState.tools[name] || { available: false, path: '' };
    const ok = !!info.available;
    const cls = ok ? 'ok' : 'missing';
    const analyzer = toolMatchesAnalyzer(name);
    const hasAnalyzer = !!analyzer;
    const checked = hasAnalyzer && isToolAnalyzerSelected(name, profileId);
    const disabled = !hasAnalyzer;
    return `
      <label class="tool-pill ${disabled ? 'tool-pill-disabled' : 'tool-pill-clickable'} ${!ok ? 'tool-pill-missing' : ''}">
        <div class="tool-top">
          <input type="checkbox" class="tool-status-checkbox" data-tool="${escapeHtml(name)}"
            ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}>
          <span class="tool-name">${escapeHtml(stylizeUi(name))}</span>
          <span class="tool-icon ${cls}">${ok ? '●' : '○'}</span>
        </div>
        <span class="tool-path">${escapeHtml(info.path || stylizeUi('not installed'))}</span>
      </label>
    `;
  }).join('');

  const internalHtml = internalTools.map((name) => {
    const analyzer = toolMatchesAnalyzer(name);
    const hasAnalyzer = !!analyzer;
    const checked = hasAnalyzer && isToolAnalyzerSelected(name, profileId);
    return `
      <label class="tool-pill tool-pill-clickable">
        <div class="tool-top">
          <input type="checkbox" class="tool-status-checkbox" data-tool="${escapeHtml(name)}"
            ${checked ? 'checked' : ''} ${!hasAnalyzer ? 'disabled' : ''}>
          <span class="tool-name">${escapeHtml(stylizeUi(name))}</span>
          <span class="tool-icon ok">✦</span>
        </div>
        <span class="tool-path">${escapeHtml(stylizeUi('internal python analyzer'))}</span>
      </label>
    `;
  }).join('');

  toolStatusEl.innerHTML = `${externalHtml}${internalHtml}` || `<div class="status-line">${stylizeUi('no tools in selected profile')}</div>`;

  if (analysisToolsEl) {
    const selectedCount = selectedAnalyzerIds(profile.id).length;
    const available = externalTools.filter((name) => profileState.tools[name]?.available).length;
    const total = externalTools.length;
    if (!total) {
      analysisToolsEl.textContent = stylizeUi(`tools: ${selectedCount} selected · ${internalTools.length} internal`);
    } else {
      analysisToolsEl.textContent = stylizeUi(`tools: ${selectedCount} selected · ${available}/${total} external + ${internalTools.length} internal`);
    }
  }
}

function syncProfileUI() {
  const profile = profileState.byId[selectedProfileId()] || profileState.byId[profileState.defaultProfile];
  if (!profile) return;

  if (profileDescriptionEl) profileDescriptionEl.textContent = stylizeUi(profile.description || '');
  if (analysisEtaEl) analysisEtaEl.textContent = stylizeUi(`eta: ${profile.eta_label || '--'}`);
  renderToolPills(profile);
  localStorage.setItem('analysisProfile', profile.id);
  if (selectedToolsInputEl) {
    selectedToolsInputEl.value = JSON.stringify(selectedAnalyzerIds(profile.id));
  }
}

if (analysisProfileSelect) {
  analysisProfileSelect.addEventListener('change', async () => {
    const profileId = selectedProfileId();
    await loadAnalyzerCatalog(profileId);
    syncProfileUI();
    syncAdvancedOptions(profileId);
  });
}

if (toolStatusEl) {
  toolStatusEl.addEventListener('change', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) return;
    if (!target.classList.contains('tool-status-checkbox')) return;
    const toolName = target.dataset.tool;
    if (toolName) toggleToolAnalyzer(toolName, target.checked);
  });
}

function compactLines(lines, maxLines = 40) {
  const filtered = lines.filter((line) => String(line || '').trim());
  if (filtered.length <= maxLines) return filtered;
  return [...filtered.slice(0, maxLines), `... (${filtered.length - maxLines} more lines)`];
}

function isBinaryJunk(text) {
  if (!text || text.length < 8) return false;
  let nonPrintable = 0;
  const sample = text.slice(0, 512);
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i);
    if (code < 32 && code !== 9 && code !== 10 && code !== 13) nonPrintable++;
    else if (code >= 127 && code <= 159) nonPrintable++;
    else if (code >= 0xf0 && code <= 0xff) nonPrintable++;
    else if (code === 0xfffd) nonPrintable++;
  }
  return nonPrintable / sample.length > 0.3;
}

function sanitizeOutput(text, maxLen = 2000) {
  if (!text) return text;
  if (isBinaryJunk(text)) {
    const len = text.length;
    const preview = Array.from(text.slice(0, 32))
      .map((ch) => {
        const code = ch.charCodeAt(0);
        return code < 32 || code >= 127 ? `\\x${code.toString(16).padStart(2, '0')}` : ch;
      })
      .join('');
    return `[binary data, ${len} bytes] ${preview}…`;
  }
  if (text.length > maxLen) {
    return text.slice(0, maxLen) + `\n… (${text.length - maxLen} more characters)`;
  }
  return text;
}

function payloadBlocks(payload) {
  const blocks = [];

  if (typeof payload?.output === 'string' && payload.output.trim()) {
    blocks.push({ title: 'payload', text: sanitizeOutput(payload.output.trim()) });
  }

  if (Array.isArray(payload?.output)) {
    const joined = compactLines(payload.output.map((line) => String(line))).join('\n');
    if (joined.trim()) blocks.push({ title: 'payload', text: sanitizeOutput(joined) });
  }

  if (payload?.decoded_text && typeof payload.decoded_text === 'object') {
    const rows = Object.entries(payload.decoded_text)
      .filter(([, value]) => value)
      .map(([key, value]) => `${key}:\n${value}`);
    if (rows.length) blocks.push({ title: 'decoded text', text: rows.join('\n\n') });
  }

  if (Array.isArray(payload?.matches) && payload.matches.length) {
    const rows = payload.matches.map((item) => `${item.plane || 'plane'} (${item.strategy || 'scan'}):\n${item.preview || ''}`);
    blocks.push({ title: 'matches', text: rows.join('\n\n') });
  }

  const details = payload?.details;
  if (details && typeof details === 'object') {
    if (typeof details.preview === 'string' && details.preview.trim()) {
      blocks.push({ title: 'preview', text: details.preview.trim() });
    }

    if (Array.isArray(details.text) && details.text.length) {
      const textRows = details.text
        .map((entry) => `${entry.keyword || 'text'}: ${entry.text || ''}`)
        .filter(Boolean)
        .join('\n\n');
      if (textRows.trim()) blocks.push({ title: 'text chunks', text: textRows });
    }

    if (details.text_channels && typeof details.text_channels === 'object') {
      const rows = Object.entries(details.text_channels)
        .map(([channel, value]) => `${channel}:\n${value.text_preview || ''}`)
        .join('\n\n');
      if (rows.trim()) blocks.push({ title: 'channel text', text: rows });
    }

    if (Array.isArray(details.file_payloads) && details.file_payloads.length) {
      const rows = details.file_payloads
        .map((entry) => `${entry.channel}:\n${entry.preview || ''}`)
        .join('\n\n');
      if (rows.trim()) blocks.push({ title: 'file payloads', text: rows });
    }

    if (Array.isArray(details.candidates) && details.candidates.length) {
      const rows = details.candidates
        .slice(0, 8)
        .map((candidate, idx) => {
          const signals = Array.isArray(candidate.signals) && candidate.signals.length
            ? `\nsignals: ${candidate.signals.join(', ')}`
            : '';
          return `${idx + 1}. ${candidate.label || candidate.option_id} (${candidate.confidence})\n${candidate.summary || ''}${signals}`;
        })
        .join('\n\n');
      blocks.push({ title: 'ranked candidates', text: rows });
    }
  }

  if (!blocks.length) {
    const fallback = payload?.error || payload?.reason || payload?.summary || 'no payload detected';
    blocks.push({ title: 'result', text: String(fallback) });
  }

  const unique = [];
  const seen = new Set();
  blocks.forEach((block) => {
    const key = `${block.title}::${block.text}`;
    if (seen.has(key)) return;
    seen.add(key);
    unique.push(block);
  });
  return unique;
}

function renderMetadata(payload) {
  const copy = {};
  Object.entries(payload || {}).forEach(([key, value]) => {
    if (['output', 'decoded_text', 'matches'].includes(key)) return;
    if (key === 'details' && value && typeof value === 'object') {
      const detailCopy = { ...value };
      delete detailCopy.preview;
      delete detailCopy.text;
      delete detailCopy.text_channels;
      delete detailCopy.file_payloads;
      delete detailCopy.candidates;
      copy[key] = detailCopy;
      return;
    }
    copy[key] = value;
  });

  if (!Object.keys(copy).length) return '';
  return `
    <details class="meta-toggle">
      <summary>${escapeHtml(stylizeUi('metadata'))}</summary>
      <pre>${escapeHtml(JSON.stringify(copy, null, 2))}</pre>
    </details>
  `;
}

function renderToolCard(toolKey, payload, wide = false) {
  if (!payload || typeof payload !== 'object') return '';

  const status = String(payload.status || 'unknown').toLowerCase();
  const label = stylizeUi(payload.label || toolKey);
  const tagClass =
    status === 'ok' ? 'ok' : status === 'error' ? 'error' : status === 'no_signal' || status === 'skipped' ? 'warn' : '';

  const confidence = typeof payload.confidence === 'number' ? payload.confidence : null;
  const timing = typeof payload.timing_ms === 'number' && payload.timing_ms > 0 ? formatDurationMs(payload.timing_ms) : '';

  const blocks = payloadBlocks(payload)
    .map((block) => `
      <div class="payload-block">
        <div class="payload-title">${escapeHtml(stylizeUi(block.title))}</div>
        <pre>${escapeHtml(block.text)}</pre>
      </div>
    `)
    .join('');

  const summary = payload.summary ? `<div class="result-summary">${escapeHtml(stylizeUi(payload.summary))}</div>` : '';
  const modeBadge = payload.mode ? `<span class="tag mode ${escapeHtml(payload.mode)}">${escapeHtml(stylizeUi(payload.mode))}</span>` : '';
  const confBadge = confidence !== null ? `<span class="tag mode">${escapeHtml(stylizeUi(`conf ${confidence}`))}</span>` : '';
  const timingBadge = timing ? `<span class="tag mode">${escapeHtml(stylizeUi(timing))}</span>` : '';
  const style = wide ? 'style="grid-column: 1 / -1;"' : '';

  return `
    <div class="result-card" ${style}>
      <div class="result-card-head">
        <h3>${escapeHtml(label)}</h3>
        <div class="tag-row">
          ${modeBadge}
          ${confBadge}
          ${timingBadge}
          <span class="tag ${tagClass}">${escapeHtml(stylizeUi(status))}</span>
        </div>
      </div>
      ${summary}
      ${blocks}
      ${renderMetadata(payload)}
    </div>
  `;
}

function isResultUseful(payload) {
  if (!payload || typeof payload !== 'object') return false;
  const status = String(payload.status || '').toLowerCase();
  if (status === 'skipped') return false;
  if (status === 'empty' && !payload.output && !payload.decoded_text && !payload.matches) return false;
  return true;
}

function renderDecodeResult(data) {
  const results = data.results || {};
  const artifacts = data.artifacts || { images: [], archives: [] };
  const meta = data.meta || {};

  const planeKeys = ['simple_rgb', 'red_plane', 'green_plane', 'blue_plane', 'alpha_plane'];
  const stringsKey = 'strings';

  const cardsPlanes = planeKeys
    .filter((key) => results[key] && isResultUseful(results[key]))
    .map((key) => renderToolCard(key, results[key]))
    .join('');

  const primary = ['invisible_unicode_decode', 'auto_detect']
    .filter((key) => results[key] && isResultUseful(results[key]))
    .map((key) => renderToolCard(key, results[key]))
    .join('');

  const rankedKeys = (results.auto_detect?.details?.candidates || [])
    .map((candidate) => candidate.option_id)
    .filter((key, idx, arr) => key && arr.indexOf(key) === idx && results[key] && isResultUseful(results[key]));

  const topCards = rankedKeys.map((key) => renderToolCard(key, results[key])).join('');

  const otherDecode = decodeOptionPriority
    .filter((key) => key !== 'auto_detect' && results[key] && !rankedKeys.includes(key) && isResultUseful(results[key]))
    .map((key) => renderToolCard(key, results[key]))
    .join('');

  const restCards = restOrder
    .filter(
      (key) =>
        results[key] &&
        isResultUseful(results[key]) &&
        !planeKeys.includes(key) &&
        !decodeOptionPriority.includes(key) &&
        key !== stringsKey &&
        key !== 'invisible_unicode_decode'
    )
    .map((key) => renderToolCard(key, results[key]))
    .join('');

  const remaining = Object.keys(results)
    .filter(
      (key) =>
        results[key] &&
        isResultUseful(results[key]) &&
        !planeKeys.includes(key) &&
        !decodeOptionPriority.includes(key) &&
        !restOrder.includes(key) &&
        key !== stringsKey &&
        key !== 'invisible_unicode_decode'
    )
    .map((key) => renderToolCard(key, results[key]))
    .join('');

  const stringsCard = results[stringsKey] && isResultUseful(results[stringsKey]) ? renderToolCard(stringsKey, results[stringsKey], true) : '';

  const gallery = (artifacts.images || [])
    .map((img) => `<div><img src="${img.data_url}" alt="${escapeHtml(img.name)}"><div class="status-line">${escapeHtml(img.name)}</div></div>`)
    .join('');

  const downloads = (artifacts.archives || [])
    .map((file) => `<a href="${file.data_url}" download="${escapeHtml(file.name)}">${escapeHtml(file.name)}</a>`)
    .join('');

  const metaLine = `
    <div class="analysis-meta-line">
      <span>${escapeHtml(stylizeUi(`profile: ${meta.profile_label || meta.profile || 'n/a'}`))}</span>
      <span>${escapeHtml(stylizeUi(`elapsed: ${formatDurationMs(meta.elapsed_ms || 0)}`))}</span>
      <span>${escapeHtml(stylizeUi(`input: ${meta.input_mime || 'unknown'}`))}</span>
    </div>
  `;

  const skippedNames = Object.entries(results)
    .filter(([, payload]) => payload && String(payload.status || '').toLowerCase() === 'skipped')
    .map(([key, payload]) => escapeHtml(stylizeUi(payload.label || key)));
  const skippedSummary = skippedNames.length
    ? `<details class="meta-toggle" style="margin-top:8px;">
        <summary>${escapeHtml(stylizeUi(`${skippedNames.length} analyzers skipped`))}</summary>
        <div style="color:var(--muted);font-size:11px;padding:8px 0;line-height:1.6;">${skippedNames.join(', ')}</div>
      </details>`
    : '';

  decodeOutput.innerHTML = `
    ${metaLine}
    ${cardsPlanes ? `<div class="result-grid priority-grid">${cardsPlanes}</div>` : ''}
    ${primary ? `<div class="result-grid">${primary}</div>` : ''}
    ${topCards ? `<div class="result-grid">${topCards}</div>` : ''}
    ${otherDecode ? `<div class="result-grid">${otherDecode}</div>` : ''}
    ${gallery ? `<h3 class="gallery-title">${escapeHtml(stylizeUi('bit-plane gallery'))}</h3><div class="gallery">${gallery}</div>` : ''}
    <div class="result-grid">${restCards}${remaining}</div>
    ${downloads ? `<div class="downloads" style="margin-top:12px;">${downloads}</div>` : ''}
    ${stringsCard ? `<div class="result-grid strings-block">${stringsCard}</div>` : ''}
    ${skippedSummary}
  `;
}

if (decodeForm) {
  decodeForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    const analyzeFile = analyzeInput && analyzeInput.files ? analyzeInput.files[0] : null;
    const analyzeError = validateImageFile(analyzeFile);
    if (analyzeError) {
      decodeOutput.innerHTML = `<div class="status-line error">${escapeHtml(stylizeUi(analyzeError))}</div>`;
      return;
    }

    const profileId = selectedProfileId();
    const fd = new FormData(decodeForm);
    fd.set('analysisProfile', profileId);
    fd.set('selectedTools', JSON.stringify(selectedAnalyzerIds(profileId)));

    showPanel('decode-panel');
    const stopTimer = startLiveTimer(stylizeUi('status: running'));
    decodeOutput.innerHTML = `<div class="status-line">${escapeHtml(stylizeUi('running analyzers…'))}</div>`;

    try {
      const res = await fetch('/api/decode', { method: 'POST', body: fd });
      const { data, text } = await readResponse(res);
      if (!res.ok) throw new Error(responseMessage(res, data, text));
      if (!data) throw new Error(responseMessage(res, data, text));
      if (data.error) throw new Error(data.error);
      renderDecodeResult(data);
      stopTimer(stylizeUi('status: complete'));
    } catch (err) {
      stopTimer(stylizeUi('status: failed'));
      decodeOutput.innerHTML = `<div class="status-line error">${escapeHtml(stylizeUi(err.message || String(err)))}</div>`;
    }
  });
}

loadProfilesAndTools();
