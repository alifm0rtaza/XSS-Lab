/**
 * Utility functions for XSS Lab v2
 * Data-flow sanitization, context escaping, layout rendering, and browser execution detection.
 */

/**
 * Escapes special characters to their corresponding HTML entities.
 * Prevents HTML injection when rendering untrusted strings in HTML body context.
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Escapes attributes for safe inclusion inside HTML attributes (e.g. value="...").
 */
export function escapeHtmlAttr(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;');
}

/**
 * Encodes strings safely for embedding inside JavaScript string literals <script>var x = "...";</script>.
 */
export function escapeJsString(str) {
  if (str === null || str === undefined) return '""';
  return JSON.stringify(String(str))
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/**
 * Sanitizes URLs to prevent javascript: and data: pseudo-protocol XSS.
 * Allows only http:, https:, mailto:, or relative paths (/path, #hash).
 */
export function sanitizeUrl(url) {
  if (!url || typeof url !== 'string') return '#';
  const trimmed = url.trim();
  
  if (trimmed.startsWith('/') || trimmed.startsWith('#')) {
    return trimmed;
  }
  
  try {
    const parsed = new URL(trimmed, 'http://localhost');
    const protocol = parsed.protocol.toLowerCase();
    if (protocol === 'http:' || protocol === 'https:' || protocol === 'mailto:') {
      return trimmed;
    }
  } catch {
    // If URL parsing fails, reject
  }
  return '#blocked-unsafe-protocol';
}

/**
 * Educational Source / Sink Visualizer Component
 */
export function renderSourceSinkVisualizer({
  source = 'User Input',
  processing = 'Server Processing',
  sink = 'HTML Response',
  destination = 'Browser DOM',
  isSecure = false
}) {
  return `
    <div class="flow-card">
      <div class="flow-title">Data Flow (${isSecure ? 'Secure Remediation' : 'Vulnerable Path'})</div>
      <div class="flow-steps">
        <div class="flow-step source">
          <span class="flow-label">Source</span>
          <span class="flow-val">${escapeHtml(source)}</span>
        </div>
        <span class="flow-arrow">→</span>
        <div class="flow-step">
          <span class="flow-label">Processing</span>
          <span class="flow-val">${escapeHtml(processing)}</span>
        </div>
        <span class="flow-arrow">→</span>
        <div class="flow-step ${isSecure ? 'sink-secure' : 'sink-vuln'}">
          <span class="flow-label">${isSecure ? 'Safe Filter / Encoder' : 'Unsafe Sink'}</span>
          <span class="flow-val">${escapeHtml(sink)}</span>
        </div>
        <span class="flow-arrow">→</span>
        <div class="flow-step">
          <span class="flow-label">Browser Target</span>
          <span class="flow-val">${escapeHtml(destination)}</span>
        </div>
      </div>
    </div>
  `;
}

/**
 * 3-Tier Navigation Component for Reflected, Stored, and DOM XSS modules.
 */
export function renderTierNav({ xssType = 'reflected', activeTier = 'main', isSecure = false }) {
  const secureSuffix = isSecure ? '/secure' : '';
  const basePath = `/labs/${xssType}`;

  const mainHref = `${basePath}/main${secureSuffix}`;
  const contextsHref = xssType === 'dom' ? `${basePath}/sources-sinks${secureSuffix}` : `${basePath}/contexts${secureSuffix}`;
  const advancedHref = `${basePath}/advanced${secureSuffix}`;

  const tier2Label = xssType === 'dom' ? 'Core Sources & Sinks' : 'Core Contexts';

  return `
    <nav class="tier-nav" aria-label="${escapeHtml(xssType)} laboratory tiers">
      <a href="${mainHref}" class="tier-tab ${activeTier === 'main' ? 'active' : ''}">
        <span>🎯 1. Main Lab</span>
        <span class="tier-tag tier-tag-rec">Recommended</span>
      </a>
      <a href="${contextsHref}" class="tier-tab ${activeTier === 'contexts' ? 'active' : ''}">
        <span>🔍 2. ${tier2Label}</span>
      </a>
      <a href="${advancedHref}" class="tier-tab ${activeTier === 'advanced' ? 'active' : ''}">
        <span>⚡ 3. Advanced Challenges</span>
        <span class="tier-tag tier-tag-adv">Advanced</span>
      </a>
    </nav>
  `;
}

/**
 * Reality Patch Status Grid: Explicitly distinguishes Reflection vs Injection vs Execution.
 */
export function renderRealityStatusGrid({
  input = '',
  isReflected = false,
  contextName = 'HTML Body',
  isPersistent = false,
  isHtmlInjected = false,
  isJsExecuted = false
}) {
  const hasInput = Boolean(input && String(input).trim());
  const reflectedVal = hasInput ? (isReflected ? 'YES' : 'NO') : 'PENDING';
  const persistentVal = isPersistent ? 'YES (Stored in Database)' : 'NO (Per-Request Only)';
  const injectedVal = hasInput ? (isHtmlInjected ? 'YES' : 'NO') : 'PENDING';

  return `
    <div class="reality-status-grid">
      <div class="reality-status-card">
        <span class="reality-status-label">Reflection Detected</span>
        <span class="reality-status-value ${!hasInput ? 'status-no' : isReflected ? 'status-yes' : 'status-no'}">
          ${reflectedVal === 'YES' ? '✅ YES' : reflectedVal === 'NO' ? '❌ NO' : '⏳ None'}
        </span>
        <span class="reality-status-desc">${isReflected ? 'Server response contains user input' : 'Input not echoed in HTTP response'}</span>
      </div>

      <div class="reality-status-card">
        <span class="reality-status-label">Output Context</span>
        <span class="reality-status-value status-neutral">
          🏷️ ${escapeHtml(contextName)}
        </span>
        <span class="reality-status-desc">Syntactic placement inside HTML document</span>
      </div>

      <div class="reality-status-card">
        <span class="reality-status-label">Persistent on Server</span>
        <span class="reality-status-value ${isPersistent ? 'status-vuln' : 'status-no'}">
          ${isPersistent ? '⚠️ YES' : '🛡️ NO'}
        </span>
        <span class="reality-status-desc">${escapeHtml(persistentVal)}</span>
      </div>

      <div class="reality-status-card">
        <span class="reality-status-label">HTML Injection</span>
        <span class="reality-status-value ${!hasInput ? 'status-no' : isHtmlInjected ? 'status-vuln' : 'status-no'}">
          ${injectedVal === 'YES' ? '⚠️ YES' : injectedVal === 'NO' ? '🛡️ NO' : '⏳ None'}
        </span>
        <span class="reality-status-desc">${isHtmlInjected ? 'Input parsed as live markup / tags' : 'Input treated strictly as text / encoded'}</span>
      </div>

      <div class="reality-status-card">
        <span class="reality-status-label">JavaScript Execution</span>
        <span class="reality-status-value ${isJsExecuted ? 'status-vuln' : 'status-no'}" id="reality-status-exec-val">
          ${isJsExecuted ? '⚡ YES' : '🔒 NO'}
        </span>
        <span class="reality-status-desc" id="reality-status-exec-desc">${isJsExecuted ? 'Verified JavaScript runtime execution' : 'No client script execution detected'}</span>
      </div>
    </div>
  `;
}

/**
 * DevTools External Verification Guide Component
 */
export function renderDevToolsGuide({ endpoint = '/reflected/search', method = 'GET', paramName = 'q', inputValue = 'LAB_TEST_123' }) {
  const encVal = encodeURIComponent(inputValue || 'LAB_TEST_123');
  const fullReq = `${method} ${endpoint}?${paramName}=${encVal}`;

  return `
    <div class="devtools-guide-card">
      <div class="devtools-guide-title">
        <span>🛠️ Real Browser DevTools Verification Guide</span>
      </div>
      <p style="font-size: 0.84rem; color: var(--text-muted); margin-bottom: 0.5rem;">
        This laboratory uses 100% genuine HTTP parameters and server processing. You can verify every step using standard browser DevTools:
      </p>
      <ol class="devtools-steps-list">
        <li>Press <kbd>F12</kbd> (or <kbd>Ctrl+Shift+I</kbd> / <kbd>Cmd+Option+I</kbd>) to open native <strong>Browser DevTools</strong>.</li>
        <li>Switch to the <strong>Network</strong> panel and submit the test form above.</li>
        <li>Inspect the actual request: <code>${escapeHtml(fullReq)}</code>.</li>
        <li>In <strong>Payload / Query String Parameters</strong>, see parameter <code>${escapeHtml(paramName)}</code> carrying your input.</li>
        <li>In <strong>Response</strong>, view the exact raw bytes returned by the Express server before browser parsing.</li>
        <li>Switch to <strong>Elements / Inspector</strong> to observe how the browser parses and places the input into the live DOM.</li>
      </ol>
    </div>
  `;
}

/**
 * Common HTML wrapper layout for clean educational navigation.
 */
export function renderLayout({ title, activeNav = '', bodyContent }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - XSS Lab</title>
  <link rel="stylesheet" href="/public/css/style.css">
</head>
<body>
  <header class="site-header">
    <div class="container header-inner">
      <div class="brand">
        <a href="/" class="brand-link">
          <span style="font-size: 1.25rem;">🛡️</span>
          <span class="brand-title">XSS <span>LAB</span></span>
        </a>
        <span class="badge badge-local">Local Security Lab</span>
      </div>
      <nav class="site-nav">
        <a href="/" class="nav-link ${activeNav === 'home' ? 'active' : ''}">Overview</a>
        <a href="/labs/reflected/main" class="nav-link ${activeNav === 'reflected' ? 'active' : ''}">Reflected</a>
        <a href="/labs/stored/main" class="nav-link ${activeNav === 'stored' ? 'active' : ''}">Stored</a>
        <a href="/labs/dom/main" class="nav-link ${activeNav === 'dom' ? 'active' : ''}">DOM</a>
        <a href="/documentation" class="nav-link ${activeNav === 'documentation' ? 'active' : ''}">Documentation</a>
        <a href="/workbench" class="nav-link ${activeNav === 'workbench' ? 'active' : ''}">Workbench</a>
        <a href="/payloads" class="nav-link ${activeNav === 'payloads' ? 'active' : ''}">Test Inputs</a>
        <button type="button" class="btn btn-secondary" style="padding: 0.25rem 0.55rem; font-size: 0.78rem; margin-left: 0.35rem;" title="Performs full factory restore of local lab and cleans lab-created demonstration sessions." onclick="restoreEntireLab()">🔄 Restore Entire Lab</button>
      </nav>
    </div>
  </header>

  <!-- Centered Educational XSS Execution Modal & Backdrop Overlay -->
  <div id="xss-execution-modal-overlay" class="xss-modal-overlay" style="display: none;" role="dialog" aria-modal="true" aria-labelledby="xss-modal-title">
    <div class="xss-modal-container">
      <div class="xss-modal-card">
        <div class="xss-modal-header">
          <div style="display: flex; align-items: center; gap: 0.6rem;">
            <span class="xss-modal-icon">⚡</span>
            <div>
              <h3 id="xss-modal-title" class="xss-modal-title">XSS Executed!</h3>
              <span id="xss-modal-type-badge" class="badge badge-vuln">Reflected XSS</span>
            </div>
          </div>
          <button type="button" class="xss-modal-close" onclick="window.closeXssModal()" aria-label="Close modal">✕</button>
        </div>
        <div class="xss-modal-body">
          <p id="xss-modal-desc" style="color: var(--text-main); font-size: 0.92rem; margin-bottom: 0.75rem;">
            JavaScript payload executed successfully in the browser client runtime.
          </p>
          <div class="xss-modal-details-box">
            <div class="xss-modal-detail-row">
              <span class="xss-modal-label">Challenge Context:</span>
              <span id="xss-modal-challenge" style="font-size: 0.85rem; font-weight: 600; color: var(--text-main);">HTML Body Context</span>
            </div>
            <div class="xss-modal-detail-row">
              <span class="xss-modal-label">Context Sink:</span>
              <code id="xss-modal-sink">HTML Body (innerHTML / unescaped interpolation)</code>
            </div>
            <div class="xss-modal-detail-row">
              <span class="xss-modal-label">Execution Source:</span>
              <span id="xss-modal-source" style="font-size: 0.85rem; color: var(--text-muted);">HTTP GET query parameter (?q=...)</span>
            </div>
            <div class="xss-modal-detail-row" style="margin-top: 0.35rem;">
              <span class="xss-modal-label">Executed Test Input / Message:</span>
              <pre id="xss-modal-payload" class="xss-modal-payload-code">XSS TEST EXECUTED</pre>
            </div>
          </div>
        </div>
        <div class="xss-modal-footer">
          <button type="button" id="xss-modal-ok-btn" class="btn btn-primary" onclick="window.closeXssModal()" style="min-width: 90px;">OK</button>
        </div>
      </div>
    </div>
  </div>

  <main class="main-content">
    <div class="container">
      ${bodyContent}
    </div>
  </main>

  <footer class="site-footer">
    <div class="container footer-inner">
      <div><strong>Cross-Site Scripting Laboratory</strong> — Educational security training application.</div>
      <div>Strictly local (<code>127.0.0.1</code>) &bull; Standard HTTP requests &bull; Inspectable with Burp Suite</div>
    </div>
  </footer>

  <script>
    // Centered Educational XSS Execution Modal & Dialog Interceptor
    (function() {
      const origAlert = window.alert;
      const origConfirm = window.confirm;
      const origPrompt = window.prompt;

      function detectCurrentContext() {
        const path = window.location.pathname;
        const search = window.location.search;
        let xssType = 'Reflected XSS';
        let challenge = 'HTML Body Context';
        let source = 'HTTP GET query parameter (?q=...)';
        let contextSink = 'HTML Body';

        if (path.includes('/stored')) {
          xssType = 'Stored XSS';
          challenge = path.includes('/advanced') ? 'Stored XSS Advanced Challenge' : 'Community Board';
          source = 'Persistent JSON Storage (data/messages.json)';
          contextSink = 'Stored Comment Rendering';
        } else if (path.includes('/dom')) {
          xssType = 'DOM-Based XSS';
          if (window.location.hash) {
            challenge = 'URL Fragment (#hash)';
            source = 'location.hash';
            contextSink = 'innerHTML sink';
          } else if (path.includes('/advanced')) {
            challenge = 'DOM XSS Advanced Challenge';
            source = 'Client Runtime Source';
            contextSink = 'DOM Sink (innerHTML / eval)';
          } else {
            challenge = 'URL Parameter (?q=...)';
            source = 'location.search';
            contextSink = 'innerHTML / DOM sink';
          }
        } else if (path.includes('/reflected')) {
          const params = new URLSearchParams(search);
          const ctx = params.get('context') || 'html_body';

          // Detect active query parameter name
          let foundParam = 'q';
          for (const k of ['q', 'search', 'name', 'message', 'id']) {
            if (params.has(k)) {
              foundParam = k;
              break;
            }
          }

          if (path.includes('/profile')) {
            challenge = 'Profile View (Parameter: ?' + foundParam + '=)';
            source = 'HTTP GET query parameter (?' + foundParam + '=...)';
            contextSink = 'User Profile Card Name';
          } else if (path.includes('/message')) {
            challenge = 'Message Banner (Parameter: ?' + foundParam + '=)';
            source = 'HTTP GET query parameter (?' + foundParam + '=...)';
            contextSink = 'Status Message Banner';
          } else if (path.includes('/item')) {
            challenge = 'Item Details (Parameter: ?' + foundParam + '=)';
            source = 'HTTP GET query parameter (?' + foundParam + '=...)';
            contextSink = 'Item Lookup Card';
          } else if (path.includes('/results')) {
            challenge = 'Search Results (Parameter: ?' + foundParam + '=)';
            source = 'HTTP GET query parameter (?' + foundParam + '=...)';
            contextSink = 'Search Results Header';
          } else if (path.includes('/advanced')) {
            challenge = 'Reflected XSS Advanced Challenge';
            source = 'HTTP GET query parameter (?' + foundParam + '=...)';
            contextSink = 'Advanced Filter / Context Sink';
          } else if (ctx === 'attribute') {
            challenge = 'HTML Attribute Context';
            source = 'HTTP GET query parameter (?' + foundParam + '=...)';
            contextSink = 'value="..." tag attribute';
          } else if (ctx === 'javascript') {
            challenge = 'JavaScript String Context';
            source = 'HTTP GET query parameter (?' + foundParam + '=...)';
            contextSink = '<script> string variable';
          } else if (ctx === 'url') {
            challenge = 'URL / HREF Context';
            source = 'HTTP GET query parameter (?' + foundParam + '=...)';
            contextSink = '<a href="..."> destination';
          } else {
            challenge = 'HTML Body Context (Parameter: ?' + foundParam + '=)';
            source = 'HTTP GET query parameter (?' + foundParam + '=...)';
            contextSink = 'HTML Body (innerHTML / unescaped interpolation)';
          }
        }

        return { xssType, challenge, source, contextSink };
      }

      function onModalKeydown(e) {
        if (e.key === 'Escape' || e.keyCode === 27) {
          window.closeXssModal();
        }
      }

      window.showXssModal = function(info) {
        info = info || {};
        const overlay = document.getElementById('xss-execution-modal-overlay');
        const titleEl = document.getElementById('xss-modal-title');
        const badgeEl = document.getElementById('xss-modal-type-badge');
        const challengeEl = document.getElementById('xss-modal-challenge');
        const sinkEl = document.getElementById('xss-modal-sink');
        const sourceEl = document.getElementById('xss-modal-source');
        const payloadEl = document.getElementById('xss-modal-payload');
        const okBtn = document.getElementById('xss-modal-ok-btn');

        if (overlay) {
          if (titleEl) titleEl.textContent = 'XSS Executed!';
          if (badgeEl) {
            badgeEl.textContent = info.type || 'XSS Executed';
            badgeEl.className = 'badge ' + (info.type === 'Reflected XSS' ? 'badge-local' : info.type === 'Stored XSS' ? 'badge-vuln' : 'badge-secure');
          }
          if (challengeEl) challengeEl.textContent = info.challenge || 'Educational Challenge';
          if (sinkEl) sinkEl.textContent = info.contextSink || 'DOM Execution Sink';
          if (sourceEl) sourceEl.textContent = info.source || 'User Input';
          if (payloadEl) payloadEl.textContent = info.payload || info.result || '(Script Execution Confirmed)';

          overlay.style.display = 'flex';
          document.removeEventListener('keydown', onModalKeydown);
          document.addEventListener('keydown', onModalKeydown);

          if (okBtn) {
            setTimeout(function() { try { okBtn.focus(); } catch(e) {} }, 50);
          }
        }
      };

      window.closeXssModal = function() {
        const overlay = document.getElementById('xss-execution-modal-overlay');
        if (overlay) {
          overlay.style.display = 'none';
        }
        document.removeEventListener('keydown', onModalKeydown);
      };

      window.__confirmExecution = function(info) {
        info = info || {};
        const context = detectCurrentContext();
        const type = info.type || context.xssType;
        const challenge = info.challenge || context.challenge;
        const source = info.source || context.source;
        const contextSink = info.contextSink || context.contextSink;
        const payload = info.payload || info.result || 'alert() dialog executed';

        window.showXssModal({
          type,
          challenge,
          source,
          contextSink,
          payload
        });
      };

      function handleExecutionEvent(msg, execMethod) {
        const info = detectCurrentContext();
        const displayMsg = (msg !== undefined && msg !== null) ? String(msg) : 'executed';
        window.__confirmExecution({
          type: info.xssType,
          challenge: info.challenge,
          source: info.source,
          contextSink: info.contextSink,
          payload: (execMethod || 'alert') + ': ' + displayMsg
        });
      }

      // Hook native dialogs to render custom centered modal
      window.alert = function(msg) {
        handleExecutionEvent(msg, 'alert');
        // Do not call blocking native alert so tests and modal flow smoothly
        return true;
      };

      window.confirm = function(msg) {
        // Only trigger execution modal for educational alert/confirm payloads, not UI reset prompts
        if (msg && (msg.includes('Reset') || msg.includes('reset') || msg.includes('Restore') || msg.includes('Clear'))) {
          try { return origConfirm.apply(window, arguments); } catch(e) { return true; }
        }
        handleExecutionEvent(msg, 'confirm');
        return true;
      };

      window.prompt = function(msg, defaultVal) {
        handleExecutionEvent(msg, 'prompt');
        return defaultVal || '';
      };

      window.__xssExecuted = function(customInfo) {
        window.__confirmExecution(customInfo || detectCurrentContext());
      };

      window.__attachFrameDetector = function(frame) {
        if (!frame) return;
        try {
          const win = frame.contentWindow;
          if (win) {
            win.alert = function(msg) {
              handleExecutionEvent(msg, 'iframe-alert');
            };
            win.confirm = function(msg) {
              handleExecutionEvent(msg, 'iframe-confirm');
              return true;
            };
            win.prompt = function(msg) {
              handleExecutionEvent(msg, 'iframe-prompt');
              return '';
            };
            win.__confirmExecution = window.__confirmExecution;
          }
        } catch(e) {}
      };
    })();

    async function restoreEntireLab() {
      if (!confirm("This will remove all local test data and terminate/reset lab-created browser demonstration state. Continue?")) return;
      try {
        const res = await fetch('/api/lab/restore', { method: 'POST' });
        const data = await res.json().catch(() => ({ success: false }));
        
        // Comprehensive browser-side cleanup
        try {
          localStorage.clear();
          sessionStorage.clear();
          // Clear cookies on local origin
          document.cookie.split(";").forEach(function(c) {
            document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
          });
        } catch(e) {}

        if (res.ok && data.success) {
          if (data.beef && data.beef.status === 'unreachable_or_auth_failed') {
            alert("XSS-Lab restored, but the local BeEF session could not be cleaned.");
          } else {
            alert("Lab restored to factory state.");
          }
          window.location.href = "/";
        } else {
          alert("Failed to restore lab state: " + (data.message || "Unknown error"));
        }
      } catch (err) {
        alert("Error restoring lab state: " + err.message);
      }
    }

    // Backward compatibility alias
    window.resetAllLabData = restoreEntireLab;
    window.restoreEntireLab = restoreEntireLab;
  </script>
</body>
</html>`;
}
