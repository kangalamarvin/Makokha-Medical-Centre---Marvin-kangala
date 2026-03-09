(function () {
  'use strict';

  function getCsrfToken() {
    try {
      const el = document.querySelector('meta[name="csrf-token"]');
      return el ? (el.getAttribute('content') || '') : '';
    } catch (e) {
      return '';
    }
  }

  async function fetchJson(url, options) {
    const opts = Object.assign(
      {
        credentials: 'same-origin',
        headers: {
          'Accept': 'application/json'
        }
      },
      options || {}
    );
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const msg = (data && (data.error || data.message)) ? String(data.error || data.message) : ('HTTP ' + r.status);
      throw new Error(msg);
    }
    return data;
  }

  function show(el) {
    if (!el) return;
    el.classList.remove('d-none');
  }
  function hide(el) {
    if (!el) return;
    el.classList.add('d-none');
  }

  function setText(el, text) {
    if (!el) return;
    el.textContent = text == null ? '' : String(text);
  }

  function safeStr(v) {
    return v == null ? '' : String(v);
  }

  function waitForCommunicationSocket(timeoutMs) {
    const started = Date.now();
    return new Promise((resolve) => {
      (function tick() {
        try {
          if (window.communicationSystem && window.communicationSystem.socket) {
            return resolve(window.communicationSystem.socket);
          }
        } catch (e) {
          // ignore
        }
        if ((Date.now() - started) > (timeoutMs || 4000)) return resolve(null);
        setTimeout(tick, 50);
      })();
    });
  }

  // ==========================
  // Emergency code overlay
  // ==========================
  let overlayEl = null;
  let repeatTimer = null;
  let silenced = false;
  let lastSpokenText = '';

  function stopRepeating() {
    try {
      if (repeatTimer) clearInterval(repeatTimer);
    } catch (e) {}
    repeatTimer = null;
    try {
      if (window.speechSynthesis) window.speechSynthesis.cancel();
    } catch (e) {}
    silenced = false;
  }

  function speak(text) {
    const t = safeStr(text).trim();
    if (!t) return;
    lastSpokenText = t;

    try {
      if (!window.speechSynthesis || !window.SpeechSynthesisUtterance) return;
      window.speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(t);
      u.lang = 'en-US';
      u.rate = 1.0;
      u.pitch = 1.0;
      u.volume = 1.0;
      window.speechSynthesis.speak(u);
    } catch (e) {
      // best-effort
    }
  }

  function startRepeatingSpeech(text) {
    const t = safeStr(text).trim();
    if (!t) return;
    stopRepeating();
    silenced = false;
    speak(t);
    repeatTimer = setInterval(() => {
      if (silenced) return;
      speak(t);
    }, 12000);
  }

  function buildSpokenPhrase(payload) {
    const codeName = safeStr(payload && payload.code_name).trim() || 'Emergency code';
    const scope = safeStr(payload && payload.scope_type).trim();
    if (scope === 'ward') {
      const wardName = safeStr(payload && payload.ward_name).trim();
      const bedNumber = safeStr(payload && payload.bed_number).trim();
      const wardPart = wardName ? ('Ward ' + wardName) : 'Ward';
      const bedPart = bedNumber ? ('Bed ' + bedNumber) : 'Bed';
      return `${codeName}. ${wardPart}. ${bedPart}.`;
    }
    if (scope === 'department') {
      const deptName = safeStr(payload && payload.department_name).trim();
      const deptPart = deptName ? ('Department ' + deptName) : 'Department';
      return `${codeName}. ${deptPart}.`;
    }
    return `${codeName}.`;
  }

  function ensureOverlay() {
    if (overlayEl) return overlayEl;
    const el = document.createElement('div');
    el.id = 'mmcEmergencyCodeOverlay';
    el.style.position = 'fixed';
    el.style.inset = '0';
    el.style.zIndex = '11000';
    el.style.display = 'none';
    el.style.alignItems = 'center';
    el.style.justifyContent = 'center';
    el.style.padding = '24px';
    el.style.background = '#b00020';
    el.style.color = '#fff';
    el.innerHTML = `
      <div style="max-width: 920px; width: 100%;">
        <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:12px; flex-wrap:wrap;">
          <div>
            <div id="mmcEmergencyCodeTitle" style="font-size: 44px; font-weight: 900; letter-spacing: 0.8px; line-height: 1.05;"></div>
            <div id="mmcEmergencyCodeLocation" style="font-size: 18px; font-weight: 600; margin-top: 10px;"></div>
            <div id="mmcEmergencyCodeMeta" style="opacity: 0.95; margin-top: 8px; font-size: 14px;"></div>
          </div>
          <div style="display:flex; gap:10px; flex-wrap:wrap;">
            <button type="button" id="mmcEmergencySilenceBtn" class="btn btn-light">Silence</button>
            <button type="button" id="mmcEmergencyRepeatBtn" class="btn btn-outline-light">Repeat</button>
            <button type="button" id="mmcEmergencyAcknowledgeBtn" class="btn btn-dark">Acknowledge</button>
          </div>
        </div>

        <div style="margin-top: 18px; background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.18); padding: 14px; border-radius: 10px;">
          <div style="font-weight: 700; margin-bottom: 6px;">Emergency Alert</div>
          <div style="font-size: 13px; opacity: 0.95;">
            This is a live in-ward/department broadcast. Follow your emergency protocol immediately.
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(el);
    overlayEl = el;

    const ack = el.querySelector('#mmcEmergencyAcknowledgeBtn');
    const silenceBtn = el.querySelector('#mmcEmergencySilenceBtn');
    const repeatBtn = el.querySelector('#mmcEmergencyRepeatBtn');

    if (ack) {
      ack.addEventListener('click', () => {
        stopRepeating();
        el.style.display = 'none';
      });
    }

    if (silenceBtn) {
      silenceBtn.addEventListener('click', () => {
        silenced = true;
        try {
          if (window.speechSynthesis) window.speechSynthesis.cancel();
        } catch (e) {}
      });
    }

    if (repeatBtn) {
      repeatBtn.addEventListener('click', () => {
        silenced = false;
        const t = lastSpokenText || buildSpokenPhrase(window.__mmcLastEmergencyPayload || {});
        speak(t);
      });
    }

    return el;
  }

  function showOverlay(payload) {
    const el = ensureOverlay();
    const title = el.querySelector('#mmcEmergencyCodeTitle');
    const location = el.querySelector('#mmcEmergencyCodeLocation');
    const meta = el.querySelector('#mmcEmergencyCodeMeta');

    const codeName = safeStr(payload && payload.code_name).trim() || 'Emergency Code';
    const scope = safeStr(payload && payload.scope_type).trim();

    const overlayColor = safeStr(payload && payload.overlay_color).trim() || '#b00020';
    el.style.background = overlayColor;

    setText(title, codeName.toUpperCase());

    if (scope === 'ward') {
      const wardName = safeStr(payload && payload.ward_name).trim();
      const bedNumber = safeStr(payload && payload.bed_number).trim();
      setText(location, `Ward: ${wardName || '-'}  |  Bed: ${bedNumber || '-'}`);
    } else if (scope === 'department') {
      const deptName = safeStr(payload && payload.department_name).trim();
      setText(location, `Department: ${deptName || '-'}`);
    } else {
      setText(location, '');
    }

    const by = payload && payload.triggered_by ? payload.triggered_by : null;
    const byName = by && by.username ? String(by.username) : '';
    const at = safeStr(payload && payload.triggered_at).trim();
    setText(meta, `Triggered by: ${byName || '-'}  |  Time: ${at || '-'}`);

    el.style.display = 'flex';
  }

  function handleEmergencyCode(payload) {
    try {
      window.__mmcLastEmergencyPayload = payload || {};
    } catch (e) {}
    showOverlay(payload);
    const phrase = buildSpokenPhrase(payload);
    startRepeatingSpeech(phrase);
  }

  // ==========================
  // Modal + trigger
  // ==========================
  let selectedCodeKey = '';
  let codesLoaded = false;
  let wardsLoaded = false;
  let deptsLoaded = false;

  function setAlert(el, msg) {
    if (!el) return;
    if (!msg) {
      hide(el);
      el.textContent = '';
      return;
    }
    el.textContent = String(msg);
    show(el);
  }

  function renderCodes(codes) {
    const container = document.getElementById('mmcEmergencyCodeList');
    if (!container) return;
    container.innerHTML = '';

    (codes || []).forEach((c) => {
      const key = safeStr(c.key).trim();
      const name = safeStr(c.name).trim();
      const desc = safeStr(c.description).trim();
      const severity = safeStr(c.severity).trim() || 'unknown';
      const conditions = Array.isArray(c.conditions) ? c.conditions : [];
      const states = Array.isArray(c.states) ? c.states : [];

      const col = document.createElement('div');
      col.className = 'col-md-6';
      col.innerHTML = `
        <div class="card h-100 mmc-code-card" data-code-key="${key}">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-start gap-2">
              <div>
                <div class="fw-bold">${name}</div>
                <div class="text-muted small">${desc}</div>
              </div>
              <span class="badge ${severity === 'critical' ? 'bg-danger' : 'bg-secondary'}">${severity}</span>
            </div>
            <details class="mt-2 small">
              <summary>Conditions & states</summary>
              <div class="mt-2">
                <div class="fw-semibold">Conditions</div>
                <ul class="mb-2">
                  ${conditions.map((x) => `<li>${String(x)}</li>`).join('')}
                </ul>
                <div class="fw-semibold">States</div>
                <ul class="mb-0">
                  ${states.map((x) => `<li>${String(x)}</li>`).join('')}
                </ul>
              </div>
            </details>
          </div>
        </div>
      `;

      col.querySelector('.mmc-code-card').addEventListener('click', () => {
        selectedCodeKey = key;
        Array.from(container.querySelectorAll('.mmc-code-card')).forEach((el) => {
          el.classList.remove('border', 'border-3', 'border-danger');
        });
        const card = col.querySelector('.mmc-code-card');
        card.classList.add('border', 'border-3', 'border-danger');
      });

      container.appendChild(col);
    });

    // Default select first code if available
    if (!selectedCodeKey && (codes || []).length) {
      const first = container.querySelector('.mmc-code-card');
      if (first) first.click();
    }
  }

  async function loadCodesIfNeeded() {
    if (codesLoaded) return;
    const res = await fetchJson('/api/emergency-codes');
    if (!res || !res.success) throw new Error((res && res.error) || 'Failed to load codes');
    renderCodes(res.codes || []);
    codesLoaded = true;
  }

  async function loadWardsIfNeeded() {
    if (wardsLoaded) return;
    const res = await fetchJson('/api/wards');
    if (!res || !res.success) throw new Error((res && res.error) || 'Failed to load wards');
    const wardSel = document.getElementById('mmcEmergencyWard');
    if (wardSel) {
      wardSel.innerHTML = '<option value=\"\">Select ward</option>';
      (res.wards || []).forEach((w) => {
        const opt = document.createElement('option');
        opt.value = String(w.id);
        opt.textContent = w.name;
        wardSel.appendChild(opt);
      });
    }
    wardsLoaded = true;
  }

  async function loadDepartmentsIfNeeded() {
    if (deptsLoaded) return;
    const res = await fetchJson('/api/outpatient-departments');
    if (!res || !res.success) throw new Error((res && res.error) || 'Failed to load departments');
    const deptSel = document.getElementById('mmcEmergencyDepartment');
    if (deptSel) {
      deptSel.innerHTML = '<option value=\"\">Select department</option>';
      (res.departments || []).forEach((d) => {
        const opt = document.createElement('option');
        opt.value = String(d.id);
        opt.textContent = d.name + (d.type ? (' (' + d.type + ')') : '');
        deptSel.appendChild(opt);
      });
    }
    deptsLoaded = true;
  }

  async function loadBedsForWard(wardId) {
    const bedSel = document.getElementById('mmcEmergencyBed');
    if (!bedSel) return;
    bedSel.innerHTML = '<option value=\"\">Loading beds...</option>';
    if (!wardId) {
      bedSel.innerHTML = '<option value=\"\">Select bed</option>';
      return;
    }
    const res = await fetchJson(`/api/wards/${encodeURIComponent(String(wardId))}/beds`);
    if (!res || !res.success) throw new Error((res && res.error) || 'Failed to load beds');
    bedSel.innerHTML = '<option value=\"\">Select bed</option>';
    (res.beds || []).forEach((b) => {
      const opt = document.createElement('option');
      opt.value = String(b.id);
      opt.textContent = `${b.bed_number} (${b.status || 'unknown'})`;
      bedSel.appendChild(opt);
    });
  }

  function updateScopeUI() {
    const scopeSel = document.getElementById('mmcEmergencyScope');
    const wardWrap = document.getElementById('mmcEmergencyScopeWard');
    const deptWrap = document.getElementById('mmcEmergencyScopeDept');
    const scope = scopeSel ? String(scopeSel.value || '').trim() : 'ward';
    if (scope === 'department') {
      hide(wardWrap);
      show(deptWrap);
    } else {
      show(wardWrap);
      hide(deptWrap);
    }
  }

  async function triggerCode() {
    const err = document.getElementById('mmcEmergencyCodeError');
    const ok = document.getElementById('mmcEmergencyCodeSuccess');
    setAlert(err, '');
    setAlert(ok, '');

    const scopeSel = document.getElementById('mmcEmergencyScope');
    const scope = scopeSel ? String(scopeSel.value || '').trim() : 'ward';

    if (!selectedCodeKey) {
      setAlert(err, 'Please select a code.');
      return;
    }

    const body = { code: selectedCodeKey, scope_type: scope };
    if (scope === 'department') {
      const deptId = (document.getElementById('mmcEmergencyDepartment') || {}).value;
      if (!deptId) {
        setAlert(err, 'Please select a department.');
        return;
      }
      body.department_id = deptId;
    } else {
      const wardId = (document.getElementById('mmcEmergencyWard') || {}).value;
      const bedId = (document.getElementById('mmcEmergencyBed') || {}).value;
      if (!wardId) {
        setAlert(err, 'Please select a ward.');
        return;
      }
      if (!bedId) {
        setAlert(err, 'Please select a bed.');
        return;
      }
      body.ward_id = wardId;
      body.bed_id = bedId;
    }

    const csrf = getCsrfToken();
    const res = await fetchJson('/api/emergency-codes/trigger', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-CSRFToken': csrf
      },
      body: JSON.stringify(body)
    });

    if (!res || !res.success) {
      throw new Error((res && res.error) || 'Failed to send code');
    }

    setAlert(ok, 'Emergency code sent.');
    try {
      // Close modal shortly after success
      setTimeout(() => {
        const modalEl = document.getElementById('mmcEmergencyCodeModal');
        if (modalEl && window.bootstrap && bootstrap.Modal) {
          const inst = bootstrap.Modal.getInstance(modalEl);
          if (inst) inst.hide();
        }
      }, 500);
    } catch (e) {}
  }

  async function init() {
    const floatBtn = document.getElementById('mmc-emergency-code-float');
    const modalEl = document.getElementById('mmcEmergencyCodeModal');
    if (!floatBtn || !modalEl) return;

    // Bind socket listener
    const socket = await waitForCommunicationSocket(6000);
    if (socket) {
      try {
        socket.on('emergency_code', (data) => {
          handleEmergencyCode(data || {});
        });
      } catch (e) {
        // ignore
      }
    }

    // Modal open
    floatBtn.addEventListener('click', async () => {
      const err = document.getElementById('mmcEmergencyCodeError');
      const ok = document.getElementById('mmcEmergencyCodeSuccess');
      setAlert(err, '');
      setAlert(ok, '');

      try {
        if (window.bootstrap && bootstrap.Modal) {
          bootstrap.Modal.getOrCreateInstance(modalEl).show();
        }
      } catch (e) {}

      try {
        await Promise.all([loadCodesIfNeeded(), loadWardsIfNeeded(), loadDepartmentsIfNeeded()]);
      } catch (e) {
        setAlert(err, e && e.message ? e.message : 'Failed to load data.');
      }
    });

    // Scope toggle
    const scopeSel = document.getElementById('mmcEmergencyScope');
    if (scopeSel) {
      scopeSel.addEventListener('change', updateScopeUI);
      updateScopeUI();
    }

    // Ward -> beds
    const wardSel = document.getElementById('mmcEmergencyWard');
    if (wardSel) {
      wardSel.addEventListener('change', async () => {
        const err = document.getElementById('mmcEmergencyCodeError');
        setAlert(err, '');
        try {
          await loadBedsForWard(String(wardSel.value || ''));
        } catch (e) {
          setAlert(err, e && e.message ? e.message : 'Failed to load beds.');
        }
      });
    }

    // Trigger button
    const triggerBtn = document.getElementById('mmcEmergencyTriggerBtn');
    if (triggerBtn) {
      triggerBtn.addEventListener('click', async () => {
        const err = document.getElementById('mmcEmergencyCodeError');
        setAlert(err, '');
        try {
          await triggerCode();
        } catch (e) {
          setAlert(err, e && e.message ? e.message : 'Failed to send code.');
        }
      });
    }
  }

  document.addEventListener('DOMContentLoaded', init);
})();

