// DOM-based XSS (Secure Counterpart Implementation - XSS Lab v2)
// Sources: location.search, location.hash, form inputs
// Safe Sinks: textContent, createTextNode, protocol-validated element.href

// === Safe Protocol Validator ===
function isSafeUrl(url) {
  if (!url || typeof url !== 'string') return false;
  const trimmed = url.trim();
  if (trimmed.startsWith('/') || trimmed.startsWith('#')) return true;
  try {
    const parsed = new URL(trimmed, window.location.origin);
    const protocol = parsed.protocol.toLowerCase();
    return protocol === 'http:' || protocol === 'https:' || protocol === 'mailto:';
  } catch {
    return false;
  }
}

// === Scenario 1: Safe DOM Text Sink (Remediated innerHTML for Query Source) ===
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
    outputEl.textContent = ''; // Clear safely
    if (value) {
      // SAFE SINK: Using createTextNode and textContent
      const prefix = document.createTextNode('Search results for: ');
      const strongEl = document.createElement('strong');
      strongEl.textContent = value; // Strictly plain text
      outputEl.appendChild(prefix);
      outputEl.appendChild(strongEl);
    } else {
      const dimSpan = document.createElement('span');
      dimSpan.style.color = 'var(--text-dim)';
      dimSpan.textContent = 'No input provided yet. Modify the parameter above.';
      outputEl.appendChild(dimSpan);
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

// === Scenario 2: Safe DOM Text Sink (Remediated innerHTML for Fragment Source) ===
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
    outputEl.textContent = '';
    if (value) {
      const prefix = document.createTextNode('Extracted from URL fragment: ');
      const strongEl = document.createElement('strong');
      strongEl.textContent = value;
      outputEl.appendChild(prefix);
      outputEl.appendChild(strongEl);
    } else {
      const dimSpan = document.createElement('span');
      dimSpan.style.color = 'var(--text-dim)';
      dimSpan.textContent = 'No fragment payload provided yet. Update the fragment above.';
      outputEl.appendChild(dimSpan);
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

// === Scenario 3: Safe Document Stream (Remediated document.write) ===
function updateScenario2(value) {
  const frame = document.getElementById('docwrite-iframe');
  if (!frame) return;
  try {
    const doc = frame.contentDocument || frame.contentWindow.document;
    doc.open();
    // SAFE INITIALIZATION: Document template without raw dynamic string interpolation
    doc.write(`
      <!DOCTYPE html>
      <html>
      <head><style>body { color: #f8fafc; font-family: sans-serif; font-size: 14px; margin: 4px 8px; background: transparent; }</style></head>
      <body>
        <div>Stream output: <span id="safe-stream-target"></span></div>
      </body>
      </html>
    `);
    doc.close();

    // SAFE SINK: Populate text content safely
    const target = doc.getElementById('safe-stream-target');
    if (target) {
      if (value) {
        target.textContent = value;
      } else {
        target.innerHTML = '<em style="color:#64748b">No document stream data yet</em>';
      }
    }
  } catch (err) {
    console.error('Error in secure iframe update:', err);
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

// === Scenario 4: Safe DOM Dynamic href Sink ===
function updateScenario3(value) {
  const linkEl = document.getElementById('dynamic-dom-link');
  const statusEl = document.getElementById('dom-link-status');
  if (!linkEl) return;

  if (!value) {
    linkEl.href = '#';
    if (statusEl) statusEl.textContent = 'Current href: #';
    return;
  }

  // SAFE VALIDATION: Whitelist check against javascript: / dangerous protocols
  if (isSafeUrl(value)) {
    linkEl.href = value;
    if (statusEl) statusEl.textContent = `Current href (Validated Safe): ${value}`;
  } else {
    linkEl.href = '#blocked-unsafe-protocol';
    if (statusEl) {
      statusEl.textContent = `Blocked unsafe protocol in URL: ${value}`;
      statusEl.style.color = '#ef4444';
    }
  }
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
  updateScenario3('');
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
