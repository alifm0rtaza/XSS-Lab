import { 
  escapeHtml, 
  renderLayout, 
  renderSourceSinkVisualizer,
  renderTierNav,
  renderRealityStatusGrid,
  renderDevToolsGuide
} from '../server/utils.js';

/**
 * 1. MAIN DOM XSS LAB (Recommended Starting Point)
 * Teaches purely client-side vulnerability flow, source-to-sink data paths, and why server responses remain untouched.
 */
export function renderDomMainLab({ isSecure = false }) {
  const clientScript = isSecure ? '/public/js/dom-secure.js' : '/public/js/dom-vuln.js';
  const actionUrl = isSecure ? '/labs/dom/main/secure' : '/labs/dom/main';

  const visualizerHtml = renderSourceSinkVisualizer({
    source: 'Browser Source (location.search / location.hash / DOM input)',
    processing: isSecure 
      ? 'Safe Client Operations (textContent, createElement, URL validation)' 
      : 'Client JavaScript Reading Source Directly into Unsafe Sinks',
    sink: isSecure ? 'Safe Sinks: textContent / safe href' : 'Unsafe Sinks: innerHTML / document.write() / raw href',
    destination: 'Browser Live DOM Tree',
    isSecure
  });

  const statusGridHtml = renderRealityStatusGrid({
    input: 'client_data',
    isReflected: false, // In DOM XSS, the server does not reflect the input
    contextName: 'Client-Side DOM Sink (innerHTML)',
    isPersistent: false,
    isHtmlInjected: !isSecure,
    isJsExecuted: false
  });

  const bodyContent = `
    <!-- Top Header & Mode Switch -->
    <div class="lab-header">
      <div class="lab-title-group">
        <h1>
          DOM-based Cross-Site Scripting (XSS)
          <span class="badge ${isSecure ? 'badge-secure' : 'badge-vuln'}">${isSecure ? 'Secure Mode' : 'Vulnerable Mode'}</span>
        </h1>
        <p class="lab-subtitle">
          Client-side JavaScript reads data from a browser source and writes it into an unsafe DOM sink without server involvement.
        </p>
      </div>
      <div class="lab-mode-switch">
        <a href="/labs/dom/main" class="mode-btn ${!isSecure ? 'active vuln' : ''}">Vulnerable</a>
        <a href="/labs/dom/main/secure" class="mode-btn ${isSecure ? 'active secure' : ''}">Secure</a>
      </div>
    </div>

    <!-- 3-Tier Navigation -->
    ${renderTierNav({ xssType: 'dom', activeTier: 'main', isSecure })}

    <!-- Crucial Architectural Distinction Callout -->
    <div style="background-color: var(--bg-card-inner); border: 1px solid var(--border-light); border-left: 4px solid var(--accent-primary); border-radius: var(--radius-md); padding: 0.85rem 1rem; margin-bottom: 1.25rem;">
      <div style="font-weight: 700; font-size: 0.92rem; color: var(--text-main); margin-bottom: 0.3rem;">
        🌐 Core Lesson: Why DOM XSS is NOT Server-Reflected XSS
      </div>
      <p style="font-size: 0.84rem; color: var(--text-muted); line-height: 1.5;">
        In server-side Reflected XSS, the Express server parses the request and embeds the payload into the HTML response. In <strong>DOM-Based XSS</strong>, the server response is static and clean. Client-side JavaScript executing in the browser reads the payload (e.g. from <code>location.search</code> or <code>location.hash</code>) and dynamically inserts it into the DOM tree. URL fragments (<code>#...</code>) are never even transmitted to the server!
      </p>
    </div>

    <!-- DOM Scenarios Subtabs -->
    <div class="sub-nav-tabs" id="dom-scenario-tabs">
      <button type="button" class="sub-tab active" onclick="switchDomScenario('scenario-query')">1. URL Query Parameter</button>
      <button type="button" class="sub-tab" onclick="switchDomScenario('scenario-fragment')">2. URL Fragment (#hash)</button>
      <button type="button" class="sub-tab" onclick="switchDomScenario('scenario-sinks')">3. Additional Sinks (document.write / href)</button>
    </div>

    <!-- Primary Interactive DOM Workspace -->
    <div class="playground-card ${isSecure ? 'secure-border' : 'vuln-border'}">

      <!-- Scenario 1: URL Query Parameter -->
      <div id="scenario-query" class="dom-scenario-section">
        <div class="card-head-row">
          <div>
            <h2>Source: URL Query Parameter (<code>location.search</code>)</h2>
            <p style="color: var(--accent-cyan); font-size: 0.88rem; margin-top: 0.2rem;">
              Client JavaScript extracts the <code>q</code> query parameter and writes it directly to the DOM sink (<code>innerHTML</code>).
            </p>
          </div>
        </div>

        <!-- Live Location Display -->
        <div style="background-color: var(--bg-card-inner); border: 1px solid var(--border-light); border-radius: 4px; padding: 0.65rem; margin-bottom: 1rem;">
          <div style="font-size: 0.78rem; font-weight: 700; color: var(--text-dim); text-transform: uppercase; margin-bottom: 0.25rem;">Target URL (Browser Location):</div>
          <div style="font-family: monospace; font-size: 0.85rem; color: var(--accent-primary); word-break: break-all;" id="display-query-url">
            ${actionUrl}?q=hello
          </div>
        </div>

        <form id="dom-form-query" onsubmit="handleScenario1Submit(event)" class="app-form">
          <div class="form-group">
            <label for="dom-input-1" class="form-label">Query Parameter Value (<code>q</code>):</label>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
              <input 
                type="text" 
                id="dom-input-1" 
                class="form-input" 
                placeholder="Enter client query string..." 
                value=""
                autocomplete="off"
                oninput="syncDomQueryDisplay(this.value)"
                style="flex: 1; min-width: 220px;"
              />
              <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Update URL &amp; Test</button>
              <button type="button" class="btn btn-secondary" onclick="setPayload1('<img src=x onerror=alert(\\'DOM XSS EXECUTED\\')>')">Try XSS Payload</button>
              <button type="button" class="btn btn-secondary" onclick="setPayload1('<b>Safe HTML Probe</b>')">Try HTML Probe</button>
              <button type="button" class="btn btn-secondary" onclick="clearScenario1()">Reset</button>
            </div>
          </div>
        </form>

        <div class="app-output-section" style="margin-top: 1rem;">
          <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">
            DOM Output Sink (${isSecure ? 'textContent (Safe text assignment)' : 'innerHTML (Unsafe markup parsing)'}):
          </div>
          <div id="dom-output-1" class="rendered-target">
            Search results for: <strong>hello</strong>
          </div>
        </div>
      </div>

      <!-- Scenario 2: URL Fragment -->
      <div id="scenario-fragment" class="dom-scenario-section" style="display: none;">
        <div class="card-head-row">
          <div>
            <h2>Source: URL Fragment (<code>location.hash</code>)</h2>
            <p style="color: var(--accent-cyan); font-size: 0.88rem; margin-top: 0.2rem;">
              Client JavaScript extracts the <code>#hash</code> from the URL and renders it. Note: Fragments are never sent to the server in HTTP requests.
            </p>
          </div>
        </div>

        <div style="background-color: var(--bg-card-inner); border: 1px solid var(--border-light); border-radius: 4px; padding: 0.65rem; margin-bottom: 1rem;">
          <div style="font-size: 0.78rem; font-weight: 700; color: var(--text-dim); text-transform: uppercase; margin-bottom: 0.25rem;">Target URL (Browser Location):</div>
          <div style="font-family: monospace; font-size: 0.85rem; color: var(--accent-primary); word-break: break-all;" id="display-hash-url">
            ${actionUrl}#hello
          </div>
        </div>

        <form id="dom-form-fragment" onsubmit="handleFragmentSubmit(event)" class="app-form">
          <div class="form-group">
            <label for="dom-input-fragment" class="form-label">Fragment Value (<code>#...</code>):</label>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
              <input 
                type="text" 
                id="dom-input-fragment" 
                class="form-input" 
                placeholder="Enter fragment string..." 
                value=""
                autocomplete="off"
                oninput="syncDomHashDisplay(this.value)"
                style="flex: 1; min-width: 220px;"
              />
              <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Update Fragment &amp; Test</button>
              <button type="button" class="btn btn-secondary" onclick="setFragmentPayload('<img src=x onerror=alert(\\'DOM HASH XSS EXECUTED\\')>')">Try Example</button>
              <button type="button" class="btn btn-secondary" onclick="clearFragment()">Reset</button>
            </div>
          </div>
        </form>

        <div class="app-output-section" style="margin-top: 1rem;">
          <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">DOM Output Sink:</div>
          <div id="dom-output-fragment" class="rendered-target">
            Extracted from URL fragment: <strong>hello</strong>
          </div>
        </div>
      </div>

      <!-- Scenario 3: Additional Sinks -->
      <div id="scenario-sinks" class="dom-scenario-section" style="display: none;">
        <div class="card-head-row">
          <div>
            <h2>Additional Sinks: <code>document.write()</code> &amp; <code>element.href</code></h2>
            <p style="color: var(--accent-cyan); font-size: 0.88rem; margin-top: 0.2rem;">
              Demonstrating dangerous DOM execution sinks that interpret markup or pseudo-protocols.
            </p>
          </div>
        </div>

        <!-- document.write sink -->
        <div style="margin-bottom: 1.25rem; padding-bottom: 1.25rem; border-bottom: 1px solid var(--border-light);">
          <h3 style="font-size: 0.95rem; font-weight: 600; margin-bottom: 0.35rem;">Sink A: <code>document.write()</code> Document Stream</h3>
          <form id="dom-form-docwrite" onsubmit="handleScenario2Submit(event)" class="app-form">
            <div class="form-group">
              <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                <input 
                  type="text" 
                  id="dom-input-2" 
                  class="form-input" 
                  placeholder="e.g. <b onmouseover=alert(1)>Hover</b> or <script>alert(1)</script>" 
                  autocomplete="off"
                  style="flex: 1; min-width: 220px;"
                />
                <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Stream to Frame</button>
                <button type="button" class="btn btn-secondary" onclick="setPayload2('<script>alert(\"DOCWRITE XSS\")<\\/script>')">Try Example</button>
                <button type="button" class="btn btn-secondary" onclick="clearScenario2()">Reset</button>
              </div>
            </div>
          </form>
          <div style="border: 1px dashed var(--border-mid); border-radius: 4px; padding: 0.5rem; min-height: 45px; background: #ffffff;">
            <iframe id="docwrite-iframe" style="width: 100%; height: 40px; border: none; background: transparent;"></iframe>
          </div>
        </div>

        <!-- element.href sink -->
        <div>
          <h3 style="font-size: 0.95rem; font-weight: 600; margin-bottom: 0.35rem;">Sink B: Dynamic <code>element.href</code> Sink</h3>
          <form id="dom-form-href" onsubmit="handleScenario3Submit(event)" class="app-form">
            <div class="form-group">
              <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                <input 
                  type="text" 
                  id="dom-input-3" 
                  class="form-input" 
                  placeholder="e.g. javascript:alert(1) or https://example.com" 
                  autocomplete="off"
                  style="flex: 1; min-width: 220px;"
                />
                <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Update Link</button>
                <button type="button" class="btn btn-secondary" onclick="setPayload3('javascript:alert(\"DOM HREF XSS\")')">Try Example</button>
                <button type="button" class="btn btn-secondary" onclick="clearScenario3()">Reset</button>
              </div>
            </div>
          </form>
          <div style="margin-top: 0.5rem;">
            <a href="#" id="dynamic-dom-link" class="msg-link" style="font-weight: 600;">🔗 Dynamic Navigation Link (Click to Activate)</a>
            <div id="dom-link-status" style="margin-top: 0.25rem; font-size: 0.78rem; color: var(--text-dim); font-family: monospace;">Current href: #</div>
          </div>
        </div>
      </div>

      <!-- Reality Matrix -->
      <div style="margin-top: 1.25rem;">
        <div style="font-size: 0.88rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem;">
          🔍 DOM Data Flow &amp; State Matrix:
        </div>
        ${statusGridHtml}
      </div>
    </div>

    <!-- Educational Drawers -->
    <div class="drawer-container">
      <details class="edu-drawer" open>
        <summary>
          <span>💡 Why &lt;script&gt; Does Not Execute in innerHTML (HTML5 Specification)</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            According to the W3C HTML5 specification, direct <code>&lt;script&gt;</code> tags inserted via <code>element.innerHTML</code> are not executed by modern browsers for security reasons.
          </p>
          <p>
            However, DOM XSS remains dangerous because elements with inline event handlers (such as <code>&lt;img src=x onerror=alert(1)&gt;</code> or <code>&lt;svg onload=alert(1)&gt;</code>) execute immediately when parsed and appended to the live document!
          </p>
        </div>
      </details>

      <details class="edu-drawer">
        <summary>
          <span>📖 DOM Source ➔ Sink Mechanics &amp; Remediation</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            DOM-Based XSS vulnerabilities reside entirely in client JavaScript.
          </p>
          <div style="margin-top: 0.75rem;">
            <h4>Client-Side Data Flow:</h4>
            ${visualizerHtml}
          </div>
          <div style="margin-top: 0.75rem;">
            <h4>Client JavaScript Code:</h4>
            <pre class="code-box"><code>${isSecure 
              ? `// SECURE: Safe DOM text manipulation\nconst value = new URLSearchParams(location.search).get('q');\nelement.textContent = value; // Safe: browser treats value strictly as plain text`
              : `// VULNERABLE: Direct innerHTML assignment\nconst value = new URLSearchParams(location.search).get('q');\nelement.innerHTML = value; // Dangerous: parses HTML and triggers event handlers`}</code></pre>
          </div>
        </div>
      </details>
    </div>

    <script>
      function switchDomScenario(scenarioId) {
        document.querySelectorAll('.dom-scenario-section').forEach(el => el.style.display = 'none');
        document.querySelectorAll('#dom-scenario-tabs .sub-tab').forEach(el => el.classList.remove('active'));
        
        const target = document.getElementById(scenarioId);
        if (target) target.style.display = 'block';
        
        const tabs = document.querySelectorAll('#dom-scenario-tabs .sub-tab');
        if (scenarioId === 'scenario-query' && tabs[0]) tabs[0].classList.add('active');
        if (scenarioId === 'scenario-fragment' && tabs[1]) tabs[1].classList.add('active');
        if (scenarioId === 'scenario-sinks' && tabs[2]) tabs[2].classList.add('active');
      }

      function syncDomQueryDisplay(val) {
        const display = document.getElementById('display-query-url');
        if (display) display.textContent = '${actionUrl}?q=' + encodeURIComponent(val);
      }

      function syncDomHashDisplay(val) {
        const display = document.getElementById('display-hash-url');
        if (display) display.textContent = '${actionUrl}#' + encodeURIComponent(val);
      }
    </script>
    <script src="${clientScript}"></script>
  `;

  return renderLayout({
    title: 'DOM-based XSS — Main Lab',
    activeNav: 'dom',
    bodyContent
  });
}

/**
 * 2. CORE SOURCES & SINKS LAB (Query, Hash, document.write, href)
 */
export function renderDomSourcesSinksLab({ isSecure = false }) {
  return renderDomMainLab({ isSecure });
}

/**
 * 3. ADVANCED DOM XSS CHALLENGES
 */
export function renderDomAdvancedLab({ isSecure = false }) {
  const bodyContent = `
    <!-- Top Header & Mode Switch -->
    <div class="lab-header">
      <div class="lab-title-group">
        <h1>
          DOM XSS — Advanced Challenges
          <span class="badge ${isSecure ? 'badge-secure' : 'badge-vuln'}">${isSecure ? 'Secure' : 'Vulnerable'}</span>
        </h1>
        <p class="lab-subtitle">Advanced client-side execution sinks, eval/setTimeout wrappers, and DOM clobbering concepts.</p>
      </div>
      <div class="lab-mode-switch">
        <a href="/labs/dom/advanced" class="mode-btn ${!isSecure ? 'active vuln' : ''}">Vulnerable</a>
        <a href="/labs/dom/advanced/secure" class="mode-btn ${isSecure ? 'active secure' : ''}">Secure</a>
      </div>
    </div>

    <!-- 3-Tier Navigation -->
    ${renderTierNav({ xssType: 'dom', activeTier: 'advanced', isSecure })}

    <div class="playground-card ${isSecure ? 'secure-border' : 'vuln-border'}">
      <div class="card-head-row">
        <div>
          <h2>Advanced DOM Execution Sinks</h2>
          <p style="color: var(--accent-cyan); font-size: 0.88rem; margin-top: 0.2rem;">
            Test high-risk browser sinks including <code>eval()</code>, <code>Function()</code>, and SVG animation triggers.
          </p>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-top: 1rem;">
        <div style="background: var(--bg-card-inner); border: 1px solid var(--border-light); border-radius: var(--radius-md); padding: 1rem;">
          <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.4rem;">1. SVG / Event Handler Triggers</h3>
          <p style="font-size: 0.82rem; color: var(--text-muted); margin-bottom: 0.75rem;">
            Explore why <code>&lt;svg onload=alert(1)&gt;</code> executes inside <code>innerHTML</code> while <code>&lt;script&gt;</code> does not.
          </p>
          <a href="/labs/dom/sources-sinks" class="btn btn-secondary" style="font-size: 0.8rem;">Open Sources &amp; Sinks</a>
        </div>

        <div style="background: var(--bg-card-inner); border: 1px solid var(--border-light); border-radius: var(--radius-md); padding: 1rem;">
          <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.4rem;">2. URL Fragment (#hash) Isolation</h3>
          <p style="font-size: 0.82rem; color: var(--text-muted); margin-bottom: 0.75rem;">
            Verify via Network DevTools that hash values never appear in HTTP requests sent to the server.
          </p>
          <a href="/labs/dom/sources-sinks#hello" class="btn btn-secondary" style="font-size: 0.8rem;">Test Hash Source</a>
        </div>

        <div style="background: var(--bg-card-inner); border: 1px solid var(--border-light); border-radius: var(--radius-md); padding: 1rem;">
          <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.4rem;">3. Interactive DOM Debugging</h3>
          <p style="font-size: 0.82rem; color: var(--text-muted); margin-bottom: 0.75rem;">
            Set DOM Breakpoints on Subtree Modifications in Chrome/Edge DevTools Elements panel.
          </p>
          <a href="/labs/dom/main" class="btn btn-secondary" style="font-size: 0.8rem;">Open Main DOM Lab</a>
        </div>
      </div>
    </div>
  `;

  return renderLayout({
    title: 'DOM XSS — Advanced Challenges',
    activeNav: 'dom',
    bodyContent
  });
}

/**
 * Universal router for DOM Lab (backward compatible with existing routes & tests)
 */
export function renderDomLab({ isSecure = false, tier = 'main' }) {
  if (tier === 'sources-sinks' || tier === 'contexts') {
    return renderDomSourcesSinksLab({ isSecure });
  }
  if (tier === 'advanced') {
    return renderDomAdvancedLab({ isSecure });
  }
  return renderDomMainLab({ isSecure });
}
