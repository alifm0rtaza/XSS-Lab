// DOM-based XSS (Vulnerable Implementation - XSS Lab v2)
// Sources: location.search, location.hash, form inputs
// Sinks: innerHTML, document.write(), element.href

// === Scenario 1: URL Query (location.search) -> innerHTML Sink ===
function updateScenario1(value, updateHistory) {
  const outputEl = document.getElementById('dom-output-1') || document.getElementById('dom-output');
  const inputEl = document.getElementById('dom-input-1') || document.getElementById('dom-input');
  const displayUrl = document.getElementById('display-query-url');

  if (inputEl) inputEl.value = value;
  const newSearch = value ? '?q=' + encodeURIComponent(value) : '';
  if (displayUrl) displayUrl.textContent = window.location.pathname + (newSearch || '?q=hello');

  if (updateHistory && window.history && window.history.replaceState) {
    try {
      window.history.replaceState({}, document.title, window.location.pathname + newSearch);
    } catch(e) {}
  }

  if (outputEl) {
    if (value) {
      // VULNERABLE SINK: Unescaped assignment to innerHTML
      outputEl.innerHTML = `Search results for: <strong>${value}</strong>`;
    } else {
      outputEl.innerHTML = '<span style="color: var(--text-dim);">No input provided yet. Modify the parameter above.</span>';
    }
  }
}

window.handleScenario1Submit = function(e) {
  if (e) e.preventDefault();
  const inputEl = document.getElementById('dom-input-1') || document.getElementById('dom-input');
  const val = inputEl ? inputEl.value : '';
  updateScenario1(val, true);
};

window.setPayload1 = function(payload) {
  const inputEl = document.getElementById('dom-input-1') || document.getElementById('dom-input');
  if (inputEl) {
    inputEl.value = payload;
    updateScenario1(payload, true);
  }
};

window.clearScenario1 = function() {
  const inputEl = document.getElementById('dom-input-1') || document.getElementById('dom-input');
  if (inputEl) inputEl.value = '';
  updateScenario1('', true);
};

// === Scenario 2: URL Fragment (#hash) -> DOM innerHTML Sink ===
function updateFragmentScenario(value, updateHistory) {
  const outputEl = document.getElementById('dom-output-fragment');
  const inputEl = document.getElementById('dom-input-fragment');
  const displayUrl = document.getElementById('display-hash-url');

  if (inputEl) inputEl.value = value;
  if (displayUrl) displayUrl.textContent = window.location.pathname + '#' + encodeURIComponent(value || 'hello');

  if (updateHistory) {
    try {
      window.location.hash = value;
    } catch(e) {}
  }

  if (outputEl) {
    if (value) {
      // VULNERABLE SINK: Unescaped assignment to innerHTML from hash
      outputEl.innerHTML = `Extracted from URL fragment: <strong>${value}</strong>`;
    } else {
      outputEl.innerHTML = '<span style="color: var(--text-dim);">No fragment payload provided yet. Update the fragment above.</span>';
    }
  }
}

window.handleFragmentSubmit = function(e) {
  if (e) e.preventDefault();
  const inputEl = document.getElementById('dom-input-fragment');
  const val = inputEl ? inputEl.value : '';
  updateFragmentScenario(val, true);
};

window.setFragmentPayload = function(payload) {
  const inputEl = document.getElementById('dom-input-fragment');
  if (inputEl) inputEl.value = payload;
  updateFragmentScenario(payload, true);
};

window.clearFragment = function() {
  const inputEl = document.getElementById('dom-input-fragment');
  if (inputEl) inputEl.value = '';
  updateFragmentScenario('', true);
};

// === Scenario 3: document.write() Stream Sink ===
function updateScenario2(value) {
  const frame = document.getElementById('docwrite-iframe');
  if (!frame) return;
  try {
    const doc = frame.contentDocument || frame.contentWindow.document;
    doc.open();
    // VULNERABLE SINK: Direct unescaped write to document stream
    doc.write(`
      <!DOCTYPE html>
      <html>
      <head><style>body { color: #f8fafc; font-family: sans-serif; font-size: 14px; margin: 4px 8px; background: transparent; }</style></head>
      <body>
        <div>Stream output: <span>${value || '<em style="color:#64748b">No document stream data yet</em>'}</span></div>
      </body>
      </html>
    `);
    doc.close();

    // Attach lab execution detector to iframe context
    if (typeof window.__attachFrameDetector === 'function') {
      window.__attachFrameDetector(frame);
    }
  } catch (err) {
    console.error('Error writing to iframe stream:', err);
  }
}

window.handleScenario2Submit = function(e) {
  if (e) e.preventDefault();
  const inputEl = document.getElementById('dom-input-2');
  const val = inputEl ? inputEl.value : '';
  updateScenario2(val);
};

window.setPayload2 = function(payload) {
  const inputEl = document.getElementById('dom-input-2');
  if (inputEl) {
    inputEl.value = payload;
    updateScenario2(payload);
  }
};

window.clearScenario2 = function() {
  const inputEl = document.getElementById('dom-input-2');
  if (inputEl) inputEl.value = '';
  updateScenario2('');
};

// === Scenario 4: DOM Dynamic href Sink ===
function updateScenario3(value) {
  const linkEl = document.getElementById('dynamic-dom-link');
  const statusEl = document.getElementById('dom-link-status');
  if (!linkEl) return;

  const targetUrl = value || '#';
  // VULNERABLE SINK: Direct assignment to element.href without protocol validation
  linkEl.href = targetUrl;
  if (statusEl) statusEl.textContent = `Current href: ${targetUrl}`;
}

window.handleScenario3Submit = function(e) {
  if (e) e.preventDefault();
  const inputEl = document.getElementById('dom-input-3');
  const val = inputEl ? inputEl.value : '';
  updateScenario3(val);
};

window.setPayload3 = function(payload) {
  const inputEl = document.getElementById('dom-input-3');
  if (inputEl) {
    inputEl.value = payload;
    updateScenario3(payload);
  }
};

window.clearScenario3 = function() {
  const inputEl = document.getElementById('dom-input-3');
  if (inputEl) inputEl.value = '';
  updateScenario3('#');
};

// Legacy compatibility helper for tests
window.setPayload = function(payload) {
  window.setPayload1(payload);
};

// Initialization on load & hashchange
function initFromSources() {
  // 1. Process URL Query (location.search)
  const urlParams = new URLSearchParams(window.location.search);
  const queryVal = urlParams.get('q') || urlParams.get('input') || '';
  if (queryVal) {
    updateScenario1(queryVal, false);
  } else {
    updateScenario1('hello', false);
  }

  // 2. Process URL Fragment (location.hash)
  if (window.location.hash) {
    const rawHash = window.location.hash.substring(1);
    let hashVal = '';
    const hashParams = new URLSearchParams(rawHash);
    if (hashParams.has('q')) {
      hashVal = hashParams.get('q');
    } else {
      hashVal = decodeURIComponent(rawHash);
    }
    updateFragmentScenario(hashVal, false);
  } else {
    updateFragmentScenario('hello', false);
  }

  // Initialize scenario 2 frame
  updateScenario2('');
}

document.addEventListener('DOMContentLoaded', () => {
  initFromSources();
  window.addEventListener('hashchange', initFromSources);

  // Backward compatibility with #dom-form
  const legacyForm = document.getElementById('dom-form');
  if (legacyForm) {
    legacyForm.addEventListener('submit', (e) => {
      e.preventDefault();
      window.handleScenario1Submit(e);
    });
  }
});
