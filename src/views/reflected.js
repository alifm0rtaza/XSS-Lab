import { 
  escapeHtml, 
  escapeHtmlAttr, 
  escapeJsString, 
  sanitizeUrl, 
  renderLayout, 
  renderSourceSinkVisualizer,
  renderTierNav,
  renderRealityStatusGrid,
  renderDevToolsGuide
} from '../server/utils.js';

/**
 * 1. MAIN REFLECTED XSS LAB (Recommended Starting Point)
 * Real HTTP parameters, transparent data flow, devtools guide, and reflection != injection != execution proof.
 */
export function renderReflectedMainLab({ isSecure = false, query = '', paramName = 'q', endpoint = '/reflected/search' }) {
  const allowedParams = ['q', 'search', 'name', 'message', 'id'];
  const activeParam = allowedParams.includes(paramName) ? paramName : 'q';
  
  // Normalize endpoint to standard registered routes
  let activeEndpoint = '/reflected/search';
  if (endpoint.includes('results') || activeParam === 'search') activeEndpoint = '/reflected/results';
  else if (endpoint.includes('profile') || activeParam === 'name') activeEndpoint = '/reflected/profile';
  else if (endpoint.includes('message') || activeParam === 'message') activeEndpoint = '/reflected/message';
  else if (endpoint.includes('item') || activeParam === 'id') activeEndpoint = '/reflected/item';
  else activeEndpoint = '/reflected/search';

  const formActionUrl = isSecure ? `${activeEndpoint}/secure` : activeEndpoint;
  const currentLabUrl = isSecure ? '/labs/reflected/main/secure' : '/labs/reflected/main';

  // Analysis of reflection and injection
  const isReflected = Boolean(query && query.length > 0);
  const isHtmlInjected = !isSecure && Boolean(query && (query.includes('<') || query.includes('>') || query.includes('"')));
  
  // Real output formatting
  const renderedOutput = isSecure
    ? (query ? `<strong>${escapeHtml(query)}</strong>` : '<span style="color: var(--text-dim);">No parameter submitted yet. Send a request below!</span>')
    : (query ? `<strong>${query}</strong>` : '<span style="color: var(--text-dim);">No parameter submitted yet. Send a request below!</span>');

  const rawReqLine = `GET ${formActionUrl}?${activeParam}=${encodeURIComponent(query || 'LAB_TEST_123')} HTTP/1.1`;

  const visualizerHtml = renderSourceSinkVisualizer({
    source: `HTTP GET Parameter (?${activeParam}=...)`,
    processing: isSecure ? `Express req.query.${activeParam} -> escapeHtml()` : `Express req.query.${activeParam} -> Raw Concatenation`,
    sink: isSecure ? 'HTML-Encoded Text' : `Direct HTML Response Interpolation (<div>\${${activeParam}}</div>)`,
    destination: 'Browser HTML Document Parser',
    isSecure
  });

  const statusGridHtml = renderRealityStatusGrid({
    input: query,
    isReflected,
    contextName: 'HTML Text / Body',
    isPersistent: false,
    isHtmlInjected,
    isJsExecuted: false // Client modal will update dynamically upon execution
  });

  const devToolsGuideHtml = renderDevToolsGuide({
    endpoint: formActionUrl,
    method: 'GET',
    paramName: activeParam,
    inputValue: query || 'LAB_TEST_123'
  });

  const bodyContent = `
    <!-- Top Header & Mode Switch -->
    <div class="lab-header">
      <div class="lab-title-group">
        <h1>
          Reflected Cross-Site Scripting (XSS)
          <span class="badge ${isSecure ? 'badge-secure' : 'badge-vuln'}">${isSecure ? 'Secure Mode' : 'Vulnerable Mode'}</span>
        </h1>
        <p class="lab-subtitle">
          Untrusted data in the HTTP request is immediately reflected in the server response without persistent storage.
        </p>
      </div>
      <div class="lab-mode-switch">
        <a href="/labs/reflected/main?endpoint=${encodeURIComponent(activeEndpoint)}&param=${activeParam}&${activeParam}=${encodeURIComponent(query)}" class="mode-btn ${!isSecure ? 'active vuln' : ''}">Vulnerable</a>
        <a href="/labs/reflected/main/secure?endpoint=${encodeURIComponent(activeEndpoint)}&param=${activeParam}&${activeParam}=${encodeURIComponent(query)}" class="mode-btn ${isSecure ? 'active secure' : ''}">Secure</a>
      </div>
    </div>

    <!-- 3-Tier Navigation -->
    ${renderTierNav({ xssType: 'reflected', activeTier: 'main', isSecure })}

    <!-- Parameter Selector Bar -->
    <div class="param-selector-bar">
      <span style="font-size: 0.78rem; font-weight: 700; color: var(--text-dim); text-transform: uppercase; margin-right: 0.25rem;">Select Parameter Endpoint:</span>
      <a href="${currentLabUrl}?endpoint=/reflected/search&param=q&q=${encodeURIComponent(query)}" class="param-pill ${activeParam === 'q' ? 'active' : ''}">
        <span>/reflected/search</span> <code>?q=</code>
      </a>
      <a href="${currentLabUrl}?endpoint=/reflected/results&param=search&search=${encodeURIComponent(query)}" class="param-pill ${activeParam === 'search' ? 'active' : ''}">
        <span>/reflected/results</span> <code>?search=</code>
      </a>
      <a href="${currentLabUrl}?endpoint=/reflected/profile&param=name&name=${encodeURIComponent(query)}" class="param-pill ${activeParam === 'name' ? 'active' : ''}">
        <span>/reflected/profile</span> <code>?name=</code>
      </a>
      <a href="${currentLabUrl}?endpoint=/reflected/message&param=message&message=${encodeURIComponent(query)}" class="param-pill ${activeParam === 'message' ? 'active' : ''}">
        <span>/reflected/message</span> <code>?message=</code>
      </a>
      <a href="${currentLabUrl}?endpoint=/reflected/item&param=id&id=${encodeURIComponent(query)}" class="param-pill ${activeParam === 'id' ? 'active' : ''}">
        <span>/reflected/item</span> <code>?id=</code>
      </a>
    </div>

    <!-- HTTP Request / Wire Representation -->
    <div class="http-wire-card">
      <div><span class="wire-method">GET</span> <span class="wire-path">${escapeHtml(formActionUrl)}?</span><span class="wire-param-key">${escapeHtml(activeParam)}</span>=<span class="wire-param-val">${escapeHtml(query ? encodeURIComponent(query) : '...')}</span> <span style="color: #94a3b8;">HTTP/1.1</span></div>
      <div style="color: #64748b; font-size: 0.75rem; margin-top: 0.2rem;">Host: 127.0.0.1:3000 &bull; Accept: text/html &bull; Parameter Name: <strong>${escapeHtml(activeParam)}</strong></div>
    </div>

    <!-- Primary Interactive Laboratory Playground Card -->
    <div class="playground-card ${isSecure ? 'secure-border' : 'vuln-border'}">
      <div class="card-head-row">
        <div>
          <h2>Target: ${escapeHtml(activeEndpoint)}</h2>
          <p style="color: var(--accent-cyan); font-size: 0.88rem; margin-top: 0.2rem;">
            Parameter <code>${escapeHtml(activeParam)}</code> is received by Express, processed on the server, and echoed into the returned HTML document.
          </p>
        </div>
        <div style="font-family: monospace; font-size: 0.78rem; color: var(--text-dim);">
          <code>Endpoint: ${escapeHtml(formActionUrl)}</code>
        </div>
      </div>

      <!-- Real Form sending actual GET request to real parameterized endpoint -->
      <form action="${formActionUrl}" method="GET" class="app-form" id="reflected-main-form">
        <div class="form-group">
          <label for="main-input" class="form-label">
            HTTP Query Parameter (<code style="color: var(--accent-primary); font-size: 0.9rem;">${escapeHtml(activeParam)}</code>):
          </label>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <input 
              type="text" 
              id="main-input" 
              name="${escapeHtmlAttr(activeParam)}" 
              class="form-input" 
              placeholder="Enter input for parameter ?${escapeHtmlAttr(activeParam)}=..." 
              value="${escapeHtml(query)}"
              autocomplete="off"
              style="flex: 1; min-width: 240px;"
            />
            <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Send Request</button>
            <button type="button" class="btn btn-secondary" onclick="setInputVal('LAB_TEST_123')">Safe Probe (LAB_TEST_123)</button>
            <button type="button" class="btn btn-secondary" onclick="setInputVal('<b>HTML_PROBE</b>')">HTML Probe (&lt;b&gt;...&lt;/b&gt;)</button>
            <button type="button" class="btn btn-secondary" onclick="setInputVal('<script>alert(\\'REFLECTED XSS EXECUTED\\')<\\/script>')">XSS Payload</button>
            <button type="button" class="btn btn-secondary" onclick="resetForm('${currentLabUrl}?endpoint=${encodeURIComponent(activeEndpoint)}&param=${activeParam}')">Reset</button>
          </div>
        </div>
      </form>

      <!-- Live Server Response Area -->
      <div class="app-output-section" style="margin-top: 1.25rem;">
        <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">
          Actual Server Response Body Output:
        </div>
        <div class="rendered-target" id="reflected-server-output">
          ${query ? `Echoed value for <code>?${escapeHtml(activeParam)}=</code>: ${renderedOutput}` : '<span style="color: var(--text-dim);">Submit input above to view server reflection.</span>'}
        </div>
      </div>

      <!-- Reality Patch Status Matrix: Reflection != Injection != Execution -->
      <div style="margin-top: 1.25rem;">
        <div style="font-size: 0.88rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem;">
          Data Flow &amp; Vulnerability State Matrix:
        </div>
        ${statusGridHtml}
      </div>
    </div>

    <!-- Real DevTools Guide -->
    ${devToolsGuideHtml}

    <!-- Educational Drawers -->
    <div class="drawer-container">
      <details class="edu-drawer" open>
        <summary>
          <span>Core Lesson: Why Reflection != HTML Injection != XSS Execution</span>
          <span>v</span>
        </summary>
        <div class="drawer-body">
          <p>A common misconception in web security is assuming that because input is echoed back, an XSS vulnerability exists. The laboratory distinguishes these distinct stages:</p>
          <div style="overflow-x: auto; margin: 0.75rem 0;">
            <table class="data-table" style="width: 100%; border-collapse: collapse; font-size: 0.84rem;">
              <thead>
                <tr style="background: var(--bg-card-inner); text-align: left;">
                  <th style="padding: 0.5rem; border: 1px solid var(--border-light);">Test Input</th>
                  <th style="padding: 0.5rem; border: 1px solid var(--border-light);">Reflection</th>
                  <th style="padding: 0.5rem; border: 1px solid var(--border-light);">HTML Injected</th>
                  <th style="padding: 0.5rem; border: 1px solid var(--border-light);">JS Execution</th>
                  <th style="padding: 0.5rem; border: 1px solid var(--border-light);">Security Meaning</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light);"><code>LAB_TEST_123</code></td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--sec-text); font-weight: 600;">YES</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--text-muted);">NO</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--text-muted);">NO</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light);">Input accepted &amp; reflected as plain alphanumeric text. Benign reflection.</td>
                </tr>
                <tr>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light);"><code>&lt;b&gt;PROBE&lt;/b&gt;</code> (Vuln mode)</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--sec-text); font-weight: 600;">YES</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--vuln-text); font-weight: 600;">YES</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--text-muted);">NO</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light);">HTML tags parsed as markup. HTML Injection confirmed, but no script executed.</td>
                </tr>
                <tr>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light);"><code>&lt;script&gt;alert(1)&lt;/script&gt;</code> (Vuln mode)</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--sec-text); font-weight: 600;">YES</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--vuln-text); font-weight: 600;">YES</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--vuln-text); font-weight: 700;">YES</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light);">Full Cross-Site Scripting. JavaScript executes in client context.</td>
                </tr>
                <tr>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light);"><code>&lt;script&gt;alert(1)&lt;/script&gt;</code> (Secure mode)</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--sec-text); font-weight: 600;">YES</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--sec-text); font-weight: 600;">NO (Encoded)</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light); color: var(--sec-text); font-weight: 600;">NO</td>
                  <td style="padding: 0.5rem; border: 1px solid var(--border-light);">Characters safely entity-encoded (<code>&amp;lt;script&amp;gt;</code>). Rendered as text.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </details>

      <details class="edu-drawer">
        <summary>
          <span>Data Flow &amp; Technical Implementation</span>
          <span>v</span>
        </summary>
        <div class="drawer-body">
          <p>
            Reflected XSS occurs when an application receives untrusted data in an HTTP request (via query parameter, form body, or headers) and immediately embeds that data into an immediate HTTP response without context-aware output encoding.
          </p>
          <div style="margin-top: 0.75rem;">
            <h4>Source -> Processing -> Sink Flow:</h4>
            ${visualizerHtml}
          </div>
          <div style="margin-top: 0.75rem;">
            <h4>Express Server Implementation:</h4>
            <pre class="code-box"><code>${isSecure 
              ? `// SECURE: Context-aware HTML entity encoding\napp.get('${escapeHtml(activeEndpoint)}/secure', (req, res) => {\n  const userInput = req.query.${escapeHtml(activeParam)} || '';\n  const safeOutput = escapeHtml(userInput);\n  res.send(\`<p>Results for: \${safeOutput}</p>\`);\n});`
              : `// VULNERABLE: Direct raw string interpolation\napp.get('${escapeHtml(activeEndpoint)}', (req, res) => {\n  const userInput = req.query.${escapeHtml(activeParam)} || '';\n  res.send(\`<p>Results for: \${userInput}</p>\`); // Unescaped reflection\n});`}</code></pre>
          </div>
        </div>
      </details>
    </div>

    <script>
      function setInputVal(val) {
        const inp = document.getElementById('main-input');
        if (inp) {
          inp.value = val;
          inp.focus();
        }
      }

      function resetForm(cleanUrl) {
        if (window.history && window.history.replaceState) {
          window.history.replaceState({}, document.title, cleanUrl);
        }
        window.location.href = cleanUrl;
      }
    </script>
  `;

  return renderLayout({
    title: `Reflected XSS — Main Lab (${activeParam})`,
    activeNav: 'reflected',
    bodyContent
  });
}

/**
 * 2. CORE CONTEXTS LAB (HTML Body, Attribute, JS String, URL / href)
 */
export function renderReflectedContextsLab({ isSecure = false, query = '', context = 'html_body' }) {
  const activeContext = ['html_body', 'attribute', 'javascript', 'url'].includes(context) ? context : 'html_body';
  const actionUrl = isSecure ? '/labs/reflected/contexts/secure' : '/labs/reflected/contexts';

  let contextTitle = '';
  let clueText = '';
  let hintText = '';
  let examplePayload = '';
  let learnMoreHtml = '';
  let codeSnippet = '';
  let realisticAppHtml = '';
  let sourceDesc = 'HTTP GET query parameter (?q=...)';
  let processingDesc = '';
  let sinkDesc = '';
  let destDesc = '';

  const isReflected = Boolean(query && query.length > 0);
  let isHtmlInjected = false;

  if (activeContext === 'html_body') {
    contextTitle = 'HTML Body Context';
    clueText = 'Your input is inserted directly into the HTML body between tags.';
    examplePayload = '<script>alert("XSS TEST EXECUTED")</script>';
    hintText = 'Supply an HTML script tag like <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> or an element with an event handler like <code>&lt;img src=x onerror=alert(1)&gt;</code>.';
    processingDesc = isSecure ? 'escapeHtml(query) entity encoding' : 'Raw string concatenation';
    sinkDesc = isSecure ? 'HTML-encoded text in body' : 'Direct HTML body interpolation (<div>${q}</div>)';
    destDesc = 'Browser HTML Parser';
    isHtmlInjected = !isSecure && Boolean(query && (query.includes('<') || query.includes('>')));

    const renderedSearchOutput = isSecure
      ? (query ? `<strong>${escapeHtml(query)}</strong>` : '<span style="color: var(--text-dim);">No search query submitted yet.</span>')
      : (query ? `<strong>${query}</strong>` : '<span style="color: var(--text-dim);">No search query submitted yet.</span>');

    realisticAppHtml = `
      <form action="${actionUrl}" method="GET" class="app-form" id="challenge-form">
        <input type="hidden" name="context" value="html_body" />
        <div class="form-group">
          <label for="search-input" class="form-label">Search Query (<code>q</code>):</label>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <input 
              type="text" 
              id="search-input" 
              name="q" 
              class="form-input" 
              placeholder="Enter search term..." 
              value="${escapeHtml(query)}"
              autocomplete="off"
              style="flex: 1; min-width: 220px;"
            />
            <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Search</button>
            <button type="button" class="btn btn-secondary" onclick="useExample('${escapeHtmlAttr(examplePayload)}')">Try Example</button>
            <button type="button" class="btn btn-secondary" onclick="resetChallenge('${actionUrl}?context=html_body')">Reset</button>
          </div>
        </div>
      </form>

      <div class="app-output-section" style="margin-top: 1rem;">
        <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">Search Results:</div>
        <div class="rendered-target">
          ${query ? `Results for: ${renderedSearchOutput}` : '<span style="color: var(--text-dim);">Submit a search query above to view results.</span>'}
        </div>
      </div>
    `;

    learnMoreHtml = `
      <p>When user input is reflected directly between HTML tags (e.g. <code>&lt;div&gt;...&lt;/div&gt;</code>), the browser HTML parser parses the response markup. If unescaped HTML elements (such as <code>&lt;script&gt;</code>) are present, the browser executes them immediately.</p>
      <p><strong>Remediation:</strong> HTML entity encoding (<code>&amp;</code> -> <code>&amp;amp;</code>, <code>&lt;</code> -> <code>&amp;lt;</code>, <code>&gt;</code> -> <code>&amp;gt;</code>, <code>"</code> -> <code>&amp;quot;</code>, <code>'</code> -> <code>&amp;#39;</code>) ensures that special characters are displayed as plain text instead of executable markup.</p>
    `;

    codeSnippet = isSecure 
      ? `// SECURE: HTML entity encode before body rendering\nconst safe = escapeHtml(req.query.q);\nres.send(\`<p>Results for: \${safe}</p>\`);`
      : `// VULNERABLE: Direct HTML interpolation\nconst raw = req.query.q;\nres.send(\`<p>Results for: \${raw}</p>\`);`;

  } else if (activeContext === 'attribute') {
    contextTitle = 'HTML Attribute Context';
    clueText = 'Your input is placed inside an HTML tag attribute (value="...").';
    examplePayload = '" onfocus="alert(\'XSS TEST EXECUTED\')" autofocus="';
    hintText = 'Break out of the double-quoted attribute with <code>"</code>, then inject an event handler such as <code>onfocus</code> or <code>onmouseover</code>.';
    processingDesc = isSecure ? 'escapeHtmlAttr(query) attribute escaping' : 'Raw unescaped attribute injection';
    sinkDesc = isSecure ? 'Quoted and escaped attribute value' : 'Unsanitized attribute insertion (<input value="${q}">)';
    destDesc = 'Browser Tag Attribute Parser';
    isHtmlInjected = !isSecure && Boolean(query && (query.includes('"') || query.includes('=')));

    const inputAttrVal = isSecure ? escapeHtmlAttr(query) : query;
    realisticAppHtml = `
      <form action="${actionUrl}" method="GET" class="app-form" id="challenge-form">
        <input type="hidden" name="context" value="attribute" />
        <div class="form-group">
          <label for="search-input" class="form-label">Filter Keyword (<code>q</code>):</label>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <input 
              type="text" 
              id="search-input" 
              name="q" 
              class="form-input" 
              placeholder="Filter keyword..." 
              value="${inputAttrVal}" 
              autocomplete="off"
              style="flex: 1; min-width: 220px;"
            />
            <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Apply Filter</button>
            <button type="button" class="btn btn-secondary" onclick="useExample('${escapeHtmlAttr(examplePayload)}')">Try Example</button>
            <button type="button" class="btn btn-secondary" onclick="resetChallenge('${actionUrl}?context=attribute')">Reset</button>
          </div>
        </div>
      </form>

      <div class="app-output-section" style="margin-top: 1rem;">
        <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">Rendered Attribute Context:</div>
        <div class="rendered-target" style="font-family: monospace; font-size: 0.88rem;">
          &lt;input type="text" value="<strong>${escapeHtml(query || '')}</strong>"&gt;
        </div>
      </div>
    `;

    learnMoreHtml = `
      <p>When user input is reflected inside an HTML attribute (e.g. <code>&lt;input value="USER_INPUT"&gt;</code>), an attacker uses matching quotes (<code>"</code>) to close the attribute early and appends active event handlers like <code>onfocus="alert(1)" autofocus</code>.</p>
      <p><strong>Remediation:</strong> Context-aware attribute escaping must convert both double quotes (<code>"</code>) and single quotes (<code>'</code>) into entity equivalents (<code>&amp;quot;</code>, <code>&amp;#39;</code>).</p>
    `;

    codeSnippet = isSecure
      ? `// SECURE: Escape attribute delimiters (", ', &, <, >)\nconst safeAttr = escapeHtmlAttr(req.query.q);\nres.send(\`<input value="\${safeAttr}">\`);`
      : `// VULNERABLE: Unescaped attribute interpolation\nconst rawAttr = req.query.q;\nres.send(\`<input value="\${rawAttr}">\`);`;

  } else if (activeContext === 'javascript') {
    contextTitle = 'JavaScript String Context';
    clueText = 'Your input is embedded inside a JavaScript string variable.';
    examplePayload = '"; alert("XSS TEST EXECUTED"); //';
    hintText = 'Break out of the string literal with <code>"; alert(1); //</code> or terminate the script block with <code>&lt;/script&gt;</code>.';
    processingDesc = isSecure ? 'escapeJsString(query) JSON serialization + tag escaping' : 'Raw insertion into JS string variable';
    sinkDesc = isSecure ? 'Safe serialized JSON literal' : '<script>var keyword = "${q}";</script>';
    destDesc = 'Browser JavaScript Engine';
    isHtmlInjected = !isSecure && Boolean(query && (query.includes('"') || query.includes(';') || query.includes('</script>')));

    let jsBlockHtml = '';
    if (query) {
      if (isSecure) {
        const safeJsStr = escapeJsString(query);
        jsBlockHtml = `
          <script id="embedded-js-reflected">
            var reflectedSearchTerm = ${safeJsStr};
            console.log('Secure JS tracking keyword:', reflectedSearchTerm);
          </script>
        `;
      } else {
        jsBlockHtml = `
          <script id="embedded-js-reflected">
            var reflectedSearchTerm = "${query}";
            console.log('Reflected tracking keyword:', reflectedSearchTerm);
          </script>
        `;
      }
    }

    realisticAppHtml = `
      <form action="${actionUrl}" method="GET" class="app-form" id="challenge-form">
        <input type="hidden" name="context" value="javascript" />
        <div class="form-group">
          <label for="search-input" class="form-label">Analytics Search Term (<code>q</code>):</label>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <input 
              type="text" 
              id="search-input" 
              name="q" 
              class="form-input" 
              placeholder="Search keyword..." 
              value="${escapeHtml(query)}" 
              autocomplete="off"
              style="flex: 1; min-width: 220px;"
            />
            <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Track Keyword</button>
            <button type="button" class="btn btn-secondary" onclick="useExample('${escapeHtmlAttr(examplePayload)}')">Try Example</button>
            <button type="button" class="btn btn-secondary" onclick="resetChallenge('${actionUrl}?context=javascript')">Reset</button>
          </div>
        </div>
      </form>

      ${jsBlockHtml}

      <div class="app-output-section" style="margin-top: 1rem;">
        <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">Client-Side Script Runtime Status:</div>
        <div class="rendered-target" style="font-size: 0.88rem;">
          ${query ? 'JavaScript tracking variable evaluated in client runtime.' : '<span style="color: var(--text-dim);">Submit a keyword to evaluate the client-side variable.</span>'}
        </div>
      </div>
    `;

    learnMoreHtml = `
      <p>When input is placed inside a <code>&lt;script&gt;</code> variable, standard HTML entity encoding does not protect against execution because the JavaScript engine interprets raw strings. Attackers break out using <code>"; alert(1); //</code>.</p>
      <p><strong>Remediation:</strong> Serialize data using <code>JSON.stringify()</code> and explicitly escape HTML script tags (<code>&lt;</code> -> <code>\\u003c</code>).</p>
    `;

    codeSnippet = isSecure
      ? `// SECURE: Serialize with JSON.stringify and escape </script> tags\nconst safeJs = escapeJsString(req.query.q);\nres.send(\`<script>var keyword = \${safeJs};</script>\`);`
      : `// VULNERABLE: Direct string interpolation in script\nconst raw = req.query.q;\nres.send(\`<script>var keyword = "\${raw}";</script>\`);`;

  } else if (activeContext === 'url') {
    contextTitle = 'URL / HREF Context';
    clueText = 'Your input influences a URL-bearing attribute (<a href="...">).';
    examplePayload = 'javascript:alert("XSS TEST EXECUTED")';
    hintText = 'Supply a <code>javascript:</code> pseudo-protocol URL. When clicked by the user, the browser executes the JavaScript code.';
    processingDesc = isSecure ? 'sanitizeUrl(query) protocol whitelist validation' : 'Raw href injection without validation';
    sinkDesc = isSecure ? 'Protocol-validated safe URL' : '<a href="${q}"> destination';
    destDesc = 'Browser Navigation Engine';
    isHtmlInjected = !isSecure && Boolean(query && query.toLowerCase().startsWith('javascript:'));

    const safeUrl = sanitizeUrl(query);
    const rawUrl = query || '#';

    realisticAppHtml = `
      <form action="${actionUrl}" method="GET" class="app-form" id="challenge-form">
        <input type="hidden" name="context" value="url" />
        <div class="form-group">
          <label for="search-input" class="form-label">Destination URL (<code>q</code>):</label>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <input 
              type="text" 
              id="search-input" 
              name="q" 
              class="form-input" 
              placeholder="e.g. https://example.com or javascript:alert(1)" 
              value="${escapeHtml(query)}"
              autocomplete="off"
              style="flex: 1; min-width: 220px;"
            />
            <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Save Link</button>
            <button type="button" class="btn btn-secondary" onclick="useExample('${escapeHtmlAttr(examplePayload)}')">Try Example</button>
            <button type="button" class="btn btn-secondary" onclick="resetChallenge('${actionUrl}?context=url')">Reset</button>
          </div>
        </div>
      </form>

      <div class="app-output-section" style="margin-top: 1rem;">
        <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">Saved Destination Link:</div>
        <div class="rendered-target">
          <a href="${isSecure ? escapeHtmlAttr(safeUrl) : rawUrl}" class="msg-link" id="reflected-url-link">
            Navigate to: ${escapeHtml(query || 'Click Here')}
          </a>
        </div>
      </div>
    `;

    learnMoreHtml = `
      <p>When user input is reflected into URL attributes (e.g. <code>&lt;a href="USER_INPUT"&gt;</code>), HTML escaping alone does NOT prevent the <code>javascript:</code> pseudo-protocol from executing when clicked.</p>
      <p><strong>Remediation:</strong> Enforce a strict protocol whitelist (allowing only <code>http:</code>, <code>https:</code>, <code>mailto:</code>, or relative paths starting with <code>/</code> or <code>#</code>).</p>
    `;

    codeSnippet = isSecure
      ? `// SECURE: Protocol whitelist verification\nconst safeLink = sanitizeUrl(req.query.q);\nres.send(\`<a href="\${escapeHtmlAttr(safeLink)}">Link</a>\`);`
      : `// VULNERABLE: Unvalidated href attribute\nconst rawLink = req.query.q;\nres.send(\`<a href="\${rawLink}">Link</a>\`);`;
  }

  const visualizerHtml = renderSourceSinkVisualizer({
    source: sourceDesc,
    processing: processingDesc,
    sink: sinkDesc,
    destination: destDesc,
    isSecure
  });

  const statusGridHtml = renderRealityStatusGrid({
    input: query,
    isReflected,
    contextName: contextTitle,
    isPersistent: false,
    isHtmlInjected,
    isJsExecuted: false
  });

  const requestSnippet = `GET ${actionUrl}?context=${activeContext}${query ? `&q=${encodeURIComponent(query)}` : ''}`;

  const bodyContent = `
    <!-- Top Header & Mode Switch -->
    <div class="lab-header">
      <div class="lab-title-group">
        <h1>
          Reflected XSS — Core Contexts (${escapeHtml(contextTitle)})
          <span class="badge ${isSecure ? 'badge-secure' : 'badge-vuln'}">${isSecure ? 'Secure' : 'Vulnerable'}</span>
        </h1>
        <p class="lab-subtitle">Explore how different syntax contexts (HTML text, attribute, script, URL) dictate breakout requirements.</p>
      </div>
      <div class="lab-mode-switch">
        <a href="/labs/reflected/contexts?context=${activeContext}&q=${encodeURIComponent(query)}" class="mode-btn ${!isSecure ? 'active vuln' : ''}">Vulnerable</a>
        <a href="/labs/reflected/contexts/secure?context=${activeContext}&q=${encodeURIComponent(query)}" class="mode-btn ${isSecure ? 'active secure' : ''}">Secure</a>
      </div>
    </div>

    <!-- 3-Tier Navigation -->
    ${renderTierNav({ xssType: 'reflected', activeTier: 'contexts', isSecure })}

    <!-- Context Sub-tabs -->
    <div class="sub-nav-tabs">
      <a href="${actionUrl}?context=html_body" class="sub-tab ${activeContext === 'html_body' ? 'active' : ''}">HTML Body</a>
      <a href="${actionUrl}?context=attribute" class="sub-tab ${activeContext === 'attribute' ? 'active' : ''}">HTML Attribute</a>
      <a href="${actionUrl}?context=javascript" class="sub-tab ${activeContext === 'javascript' ? 'active' : ''}">JavaScript String</a>
      <a href="${actionUrl}?context=url" class="sub-tab ${activeContext === 'url' ? 'active' : ''}">URL / HREF</a>
    </div>

    <!-- Primary Attack / Playground Area -->
    <div class="playground-card ${isSecure ? 'secure-border' : 'vuln-border'}">
      <div class="card-head-row">
        <div>
          <h2>Target: ${escapeHtml(contextTitle)}</h2>
          <p style="color: var(--accent-cyan); font-size: 0.88rem; margin-top: 0.2rem;">${escapeHtml(clueText)}</p>
        </div>
        <div style="font-family: monospace; font-size: 0.78rem; color: var(--text-dim);">
          <code>${escapeHtml(requestSnippet)}</code>
        </div>
      </div>

      ${realisticAppHtml}

      <div style="margin-top: 1.25rem;">
        <div style="font-size: 0.88rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem;">
          Data Flow &amp; State Matrix:
        </div>
        ${statusGridHtml}
      </div>
    </div>

    <!-- Expandable Educational Drawers -->
    <div class="drawer-container">
      <details class="edu-drawer">
        <summary>
          <span>Context Hint</span>
          <span>v</span>
        </summary>
        <div class="drawer-body">
          <p>${hintText}</p>
        </div>
      </details>

      <details class="edu-drawer">
        <summary>
          <span>Technical Explanation</span>
          <span>v</span>
        </summary>
        <div class="drawer-body">
          ${learnMoreHtml}
          <div style="margin-top: 1rem;">
            <h4>Source -> Sink Data Flow:</h4>
            ${visualizerHtml}
          </div>
          <div style="margin-top: 1rem;">
            <h4>Server Implementation:</h4>
            <pre class="code-box"><code>${codeSnippet}</code></pre>
          </div>
        </div>
      </details>
    </div>

    <script>
      function useExample(val) {
        const input = document.getElementById('search-input');
        if (input) {
          input.value = val;
          input.focus();
        }
      }

      function resetChallenge(cleanUrl) {
        if (window.history && window.history.replaceState) {
          window.history.replaceState({}, document.title, cleanUrl);
        }
        window.location.href = cleanUrl;
      }
    </script>
  `;

  return renderLayout({
    title: `Reflected XSS — ${contextTitle}`,
    activeNav: 'reflected',
    bodyContent
  });
}

/**
 * 3. ADVANCED REFLECTED XSS CHALLENGES
 */
export function renderReflectedAdvancedLab({ isSecure = false, query = '', challenge = 'tag_filter' }) {
  const activeChallenge = ['tag_filter', 'attr_event', 'script_close', 'protocol_bypass'].includes(challenge) ? challenge : 'tag_filter';
  const actionUrl = isSecure ? '/labs/reflected/advanced/secure' : '/labs/reflected/advanced';

  let challengeTitle = '';
  let challengeDesc = '';
  let examplePayload = '';
  let serverCode = '';
  let renderedOutput = '';

  const isReflected = Boolean(query && query.length > 0);
  let isHtmlInjected = false;

  if (activeChallenge === 'tag_filter') {
    challengeTitle = 'Filter Evasion: Incomplete Tag Blacklist';
    challengeDesc = 'The server uses a simplistic regex blacklist that strips lowercase <code>&lt;script&gt;</code> tags once.';
    examplePayload = '<SCRIPT>alert("FILTER BYPASSED")</SCRIPT>';
    
    // Server processing simulation
    let processed = query;
    if (isSecure) {
      processed = escapeHtml(query);
    } else {
      // Incomplete blacklist: strips single lowercase <script> only
      processed = query.replace('<script>', '').replace('</script>', '');
      isHtmlInjected = Boolean(processed.includes('<') && processed.includes('>'));
    }

    renderedOutput = isSecure ? escapeHtml(query) : processed;

    serverCode = isSecure
      ? `// SECURE: Comprehensive HTML entity encoding\nconst safe = escapeHtml(req.query.q);`
      : `// FLAWED DEFENSE: Naive case-sensitive single replacement\nconst flawed = req.query.q.replace('<script>', '').replace('</script>', '');\n// Bypasses: <SCRIPT>, <scri<script>pt>, or <img src=x onerror=alert(1)>`;

  } else if (activeChallenge === 'attr_event') {
    challengeTitle = 'Attribute Event Handler Injection (Unquoted / Focus)';
    challengeDesc = 'Input is reflected inside an unquoted or custom attribute where spaces trigger new event handlers.';
    examplePayload = 'x onfocus=alert("ATTR_EVENT") autofocus';
    
    if (isSecure) {
      renderedOutput = `<input type="text" data-filter="${escapeHtmlAttr(query)}" placeholder="Filtered view..." />`;
    } else {
      renderedOutput = `<input type="text" data-filter="${query}" placeholder="Filtered view..." />`;
      isHtmlInjected = Boolean(query.includes('onfocus') || query.includes('onerror') || query.includes('"'));
    }

    serverCode = isSecure
      ? `// SECURE: Full attribute quotation and entity escaping\nconst safe = escapeHtmlAttr(req.query.q);\nres.send(\`<input data-filter="\${safe}">\`);`
      : `// VULNERABLE: Direct attribute reflection\nres.send(\`<input data-filter="\${req.query.q}">\`);`;

  } else if (activeChallenge === 'script_close') {
    challengeTitle = 'Script Block Breakout (</script> Termination)';
    challengeDesc = 'Input is inside a script variable, but can terminate the entire script element early using <code>&lt;/script&gt;</code>.';
    examplePayload = '</script><script>alert("SCRIPT_CLOSE")</script>';

    if (isSecure) {
      renderedOutput = `<script>var tracked = ${escapeJsString(query)};</script>`;
    } else {
      renderedOutput = `<script>var tracked = "${query}";</script>`;
      isHtmlInjected = Boolean(query.includes('</script>'));
    }

    serverCode = isSecure
      ? `// SECURE: JSON.stringify + escape </script> to \\u003c/script\\u003e\nconst safe = escapeJsString(req.query.q);\nres.send(\`<script>var tracked = \${safe};</script>\`);`
      : `// VULNERABLE: Direct string interpolation inside script block\nres.send(\`<script>var tracked = "\${req.query.q}";</script>\`);`;

  } else if (activeChallenge === 'protocol_bypass') {
    challengeTitle = 'URL Protocol Whitelist & Case Evasion';
    challengeDesc = 'Input is reflected into a navigation link (<a href="...">).';
    examplePayload = 'javascript:alert("PROTOCOL_BYPASS")';

    if (isSecure) {
      renderedOutput = `<a href="${escapeHtmlAttr(sanitizeUrl(query))}" class="msg-link">Navigate to Saved URL</a>`;
    } else {
      renderedOutput = `<a href="${query || '#'}" class="msg-link">Navigate to Saved URL</a>`;
      isHtmlInjected = Boolean(query.toLowerCase().startsWith('javascript:'));
    }

    serverCode = isSecure
      ? `// SECURE: Strict protocol whitelist (http, https, mailto, relative)\nconst safe = sanitizeUrl(req.query.q);\nres.send(\`<a href="\${escapeHtmlAttr(safe)}">Link</a>\`);`
      : `// VULNERABLE: Unvalidated href attribute\nres.send(\`<a href="\${req.query.q}">Link</a>\`);`;
  }

  const statusGridHtml = renderRealityStatusGrid({
    input: query,
    isReflected,
    contextName: challengeTitle,
    isPersistent: false,
    isHtmlInjected,
    isJsExecuted: false
  });

  const bodyContent = `
    <!-- Top Header & Mode Switch -->
    <div class="lab-header">
      <div class="lab-title-group">
        <h1>
          Reflected XSS — Advanced Challenges
          <span class="badge ${isSecure ? 'badge-secure' : 'badge-vuln'}">${isSecure ? 'Secure' : 'Vulnerable'}</span>
        </h1>
        <p class="lab-subtitle">Specialized filter evasions, parser edge cases, and context breakout challenges.</p>
      </div>
      <div class="lab-mode-switch">
        <a href="/labs/reflected/advanced?challenge=${activeChallenge}&q=${encodeURIComponent(query)}" class="mode-btn ${!isSecure ? 'active vuln' : ''}">Vulnerable</a>
        <a href="/labs/reflected/advanced/secure?challenge=${activeChallenge}&q=${encodeURIComponent(query)}" class="mode-btn ${isSecure ? 'active secure' : ''}">Secure</a>
      </div>
    </div>

    <!-- 3-Tier Navigation -->
    ${renderTierNav({ xssType: 'reflected', activeTier: 'advanced', isSecure })}

    <!-- Challenge Sub-tabs -->
    <div class="sub-nav-tabs">
      <a href="${actionUrl}?challenge=tag_filter" class="sub-tab ${activeChallenge === 'tag_filter' ? 'active' : ''}">1. Tag Blacklist Evasion</a>
      <a href="${actionUrl}?challenge=attr_event" class="sub-tab ${activeChallenge === 'attr_event' ? 'active' : ''}">2. Attribute Event Handler</a>
      <a href="${actionUrl}?challenge=script_close" class="sub-tab ${activeChallenge === 'script_close' ? 'active' : ''}">3. Script Tag Closure</a>
      <a href="${actionUrl}?challenge=protocol_bypass" class="sub-tab ${activeChallenge === 'protocol_bypass' ? 'active' : ''}">4. Protocol Whitelist</a>
    </div>

    <!-- Playground Card -->
    <div class="playground-card ${isSecure ? 'secure-border' : 'vuln-border'}">
      <div class="card-head-row">
        <div>
          <h2>${escapeHtml(challengeTitle)}</h2>
          <p style="color: var(--accent-cyan); font-size: 0.88rem; margin-top: 0.2rem;">${challengeDesc}</p>
        </div>
      </div>

      <form action="${actionUrl}" method="GET" class="app-form">
        <input type="hidden" name="challenge" value="${activeChallenge}" />
        <div class="form-group">
          <label for="adv-input" class="form-label">Challenge Test Input (<code>q</code>):</label>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <input 
              type="text" 
              id="adv-input" 
              name="q" 
              class="form-input" 
              placeholder="Enter bypass test input..." 
              value="${escapeHtml(query)}"
              autocomplete="off"
              style="flex: 1; min-width: 220px;"
            />
            <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Test Challenge</button>
            <button type="button" class="btn btn-secondary" onclick="setAdvInput('${escapeHtmlAttr(examplePayload)}')">Try Example</button>
            <button type="button" class="btn btn-secondary" onclick="window.location.href='${actionUrl}?challenge=${activeChallenge}'">Reset</button>
          </div>
        </div>
      </form>

      <div class="app-output-section" style="margin-top: 1rem;">
        <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem;">Server Output:</div>
        <div class="rendered-target">
          ${query ? renderedOutput : '<span style="color: var(--text-dim);">Submit input above to evaluate challenge defense.</span>'}
        </div>
      </div>

      <div style="margin-top: 1.25rem;">
        <div style="font-size: 0.88rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem;">
          Data Flow &amp; State Matrix:
        </div>
        ${statusGridHtml}
      </div>
    </div>

    <!-- Technical Details Drawer -->
    <div class="drawer-container">
      <details class="edu-drawer">
        <summary>
          <span>Defense Breakdown &amp; Server Implementation</span>
          <span>v</span>
        </summary>
        <div class="drawer-body">
          <pre class="code-box"><code>${serverCode}</code></pre>
        </div>
      </details>
    </div>

    <script>
      function setAdvInput(val) {
        const inp = document.getElementById('adv-input');
        if (inp) {
          inp.value = val;
          inp.focus();
        }
      }
    </script>
  `;

  return renderLayout({
    title: `Reflected XSS — ${challengeTitle}`,
    activeNav: 'reflected',
    bodyContent
  });
}

/**
 * Universal router for Reflected Lab (backward compatible with existing tests)
 */
export function renderReflectedLab({ 
  isSecure = false, 
  query = '', 
  context = 'html_body', 
  tier = 'main',
  paramName = 'q',
  endpoint = '/reflected/search',
  challenge = 'tag_filter'
}) {
  if (tier === 'contexts' || (context && context !== 'html_body' && tier !== 'main')) {
    return renderReflectedContextsLab({ isSecure, query, context });
  }
  if (tier === 'advanced' || (challenge && challenge !== 'tag_filter')) {
    return renderReflectedAdvancedLab({ isSecure, query, challenge });
  }
  // Default to Main Lab
  return renderReflectedMainLab({ isSecure, query, paramName, endpoint });
}

/**
 * Standalone realistic parameterized scenario renderer
 * For direct endpoints: /reflected/search?q=..., /reflected/results?search=..., etc.
 */
export function renderReflectedParamScenario({ 
  isSecure = false, 
  endpoint = '/reflected/search', 
  paramName = 'q', 
  inputValue = '' 
}) {
  return renderReflectedMainLab({
    isSecure,
    query: inputValue,
    paramName,
    endpoint
  });
}
