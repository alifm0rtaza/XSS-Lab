import { renderLayout } from '../server/utils.js';

export function renderWorkbenchPage() {
  const bodyContent = `
    <div class="lab-header">
      <div class="lab-title-group">
        <h1>
          Testing Workbench
          <span class="badge badge-local">Local Inspection</span>
        </h1>
        <p class="lab-subtitle">Dispatch test requests directly to local lab endpoints and inspect raw HTTP responses</p>
      </div>
    </div>

    <!-- Testing Matrix Summary -->
    <div class="playground-card" style="margin-bottom: 1.25rem;">
      <div class="card-head-row">
        <h2>Local Endpoint Testing Matrix</h2>
      </div>
      <p style="color: var(--text-muted); font-size: 0.88rem; margin-bottom: 1rem;">
        Reference summary of local endpoints, methods, and output contexts across vulnerable and secure modes.
      </p>

      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Target Lab</th>
              <th>Endpoint Route</th>
              <th>Method</th>
              <th>Parameter</th>
              <th>Context</th>
              <th>Vulnerable Behavior</th>
              <th>Secure Remediation</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Reflected (Body)</strong></td>
              <td><code>/labs/reflected</code></td>
              <td><code>GET</code></td>
              <td><code>q</code></td>
              <td>HTML Body</td>
              <td><span class="status-tag vuln">Unescaped HTML</span></td>
              <td><span class="status-tag secure">HTML Entity Encoding</span></td>
            </tr>
            <tr>
              <td><strong>Reflected (Attribute)</strong></td>
              <td><code>/labs/reflected?context=attribute</code></td>
              <td><code>GET</code></td>
              <td><code>q</code></td>
              <td>HTML Attribute</td>
              <td><span class="status-tag vuln">Attribute Breakout (")</span></td>
              <td><span class="status-tag secure">Attribute Escaping</span></td>
            </tr>
            <tr>
              <td><strong>Reflected (JS String)</strong></td>
              <td><code>/labs/reflected?context=javascript</code></td>
              <td><code>GET</code></td>
              <td><code>q</code></td>
              <td>JS String Variable</td>
              <td><span class="status-tag vuln">String Breakout (";)</span></td>
              <td><span class="status-tag secure">JSON.stringify &amp; Tag Escaping</span></td>
            </tr>
            <tr>
              <td><strong>Reflected (URL/href)</strong></td>
              <td><code>/labs/reflected?context=url</code></td>
              <td><code>GET</code></td>
              <td><code>q</code></td>
              <td><code>&lt;a href="..."&gt;</code></td>
              <td><span class="status-tag vuln">javascript: Protocol</span></td>
              <td><span class="status-tag secure">Protocol Whitelisting</span></td>
            </tr>
            <tr>
              <td><strong>Stored Board</strong></td>
              <td><code>/labs/stored</code></td>
              <td><code>POST / GET</code></td>
              <td><code>author, content, website</code></td>
              <td>Datastore ➔ HTML &amp; href</td>
              <td><span class="status-tag vuln">Persistent Script Execution</span></td>
              <td><span class="status-tag secure">Output Encoding &amp; URL Sanitization</span></td>
            </tr>
            <tr>
              <td><strong>DOM XSS (innerHTML)</strong></td>
              <td><code>/labs/dom</code></td>
              <td><code>Client GET</code></td>
              <td><code>?q=... or #...</code></td>
              <td>Client DOM Sink</td>
              <td><span class="status-tag vuln">Direct innerHTML Parse</span></td>
              <td><span class="status-tag secure">element.textContent</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Controlled Local Request Dispatcher -->
    <div class="playground-card">
      <div class="card-head-row">
        <h2>Local Request Dispatcher</h2>
      </div>
      <p style="color: var(--text-muted); font-size: 0.88rem; margin-bottom: 1rem;">
        Send a test request to inspect response status, headers, and body content.
      </p>

      <form id="workbench-form" onsubmit="executeWorkbenchTest(event)" class="app-form">
        <div class="form-row-grid">
          <div class="form-group">
            <label for="wb-endpoint" class="form-label">Target Endpoint:</label>
            <select id="wb-endpoint" class="form-input" onchange="updateWorkbenchDefaults()">
              <option value="/labs/reflected">Reflected Lab (Vulnerable) - /labs/reflected</option>
              <option value="/labs/reflected/secure">Reflected Lab (Secure) - /labs/reflected/secure</option>
              <option value="/labs/reflected?context=attribute">Reflected Attribute (Vulnerable)</option>
              <option value="/labs/reflected/secure?context=attribute">Reflected Attribute (Secure)</option>
              <option value="/labs/reflected?context=javascript">Reflected JS String (Vulnerable)</option>
              <option value="/labs/reflected/secure?context=javascript">Reflected JS String (Secure)</option>
              <option value="/labs/reflected?context=url">Reflected URL Context (Vulnerable)</option>
              <option value="/labs/reflected/secure?context=url">Reflected URL Context (Secure)</option>
              <option value="/api/stored/messages">Stored API Endpoint - /api/stored/messages</option>
            </select>
          </div>

          <div class="form-group">
            <label for="wb-method" class="form-label">HTTP Method:</label>
            <select id="wb-method" class="form-input">
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
          </div>
        </div>

        <div class="form-group">
          <label for="wb-param-name" class="form-label">Parameter Name:</label>
          <input type="text" id="wb-param-name" class="form-input" value="q" />
        </div>

        <div class="form-group">
          <label for="wb-payload" class="form-label">Test Input String:</label>
          <input 
            type="text" 
            id="wb-payload" 
            class="form-input" 
            value="<script>alert('Workbench Test')</script>" 
            placeholder="Enter test string..." 
          />
        </div>

        <div class="btn-group">
          <button type="submit" class="btn btn-primary" id="wb-submit-btn">Send Local Request</button>
          <button type="button" class="btn btn-secondary" onclick="presetPayload('<img src=x onerror=alert(1)>')">&lt;img onerror&gt;</button>
          <button type="button" class="btn btn-secondary" onclick="presetPayload('&quot; onfocus=&quot;alert(1)&quot; autofocus=&quot;')">Attribute Breakout</button>
          <button type="button" class="btn btn-secondary" onclick="presetPayload('javascript:alert(1)')">javascript: URL</button>
        </div>
      </form>

      <!-- Response Inspector Output -->
      <div id="wb-response-area" style="display: none; margin-top: 1.25rem; border-top: 1px solid var(--border-light); padding-top: 1rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <strong style="font-size: 0.95rem; color: var(--text-main);">HTTP Response Inspector</strong>
          <span id="wb-response-status" style="font-family: monospace; font-size: 0.85rem; font-weight: 600;">Status: -</span>
        </div>
        
        <div style="margin-bottom: 0.75rem;">
          <div style="font-size: 0.78rem; font-weight: 600; color: var(--text-dim); text-transform: uppercase; margin-bottom: 0.25rem;">Response Headers:</div>
          <pre id="wb-response-headers" class="code-box" style="max-height: 100px; font-size: 0.75rem;"></pre>
        </div>

        <div>
          <div style="font-size: 0.78rem; font-weight: 600; color: var(--text-dim); text-transform: uppercase; margin-bottom: 0.25rem;">Response Body Snippet:</div>
          <pre id="wb-response-body" class="code-box" style="max-height: 220px; white-space: pre-wrap; word-break: break-all;"></pre>
        </div>

        <div id="wb-verdict" style="margin-top: 0.75rem; padding: 0.65rem 0.85rem; border-radius: 4px; font-size: 0.85rem;">
          <!-- Evaluation Verdict -->
        </div>
      </div>
    </div>

    <script>
      function presetPayload(str) {
        document.getElementById('wb-payload').value = str;
      }

      function updateWorkbenchDefaults() {
        const endpoint = document.getElementById('wb-endpoint').value;
        const methodSelect = document.getElementById('wb-method');
        const paramInput = document.getElementById('wb-param-name');
        
        if (endpoint.startsWith('/api/stored/messages')) {
          methodSelect.value = 'POST';
          paramInput.value = 'content';
        } else {
          methodSelect.value = 'GET';
          paramInput.value = 'q';
        }
      }

      async function executeWorkbenchTest(e) {
        e.preventDefault();
        const endpoint = document.getElementById('wb-endpoint').value;
        const method = document.getElementById('wb-method').value;
        const paramName = document.getElementById('wb-param-name').value.trim();
        const payload = document.getElementById('wb-payload').value;

        const respArea = document.getElementById('wb-response-area');
        const statusEl = document.getElementById('wb-response-status');
        const headersEl = document.getElementById('wb-response-headers');
        const bodyEl = document.getElementById('wb-response-body');
        const verdictEl = document.getElementById('wb-verdict');

        respArea.style.display = 'block';
        statusEl.textContent = 'Status: Fetching...';
        bodyEl.textContent = 'Sending local request...';
        verdictEl.textContent = '';
        verdictEl.className = '';

        try {
          let url = endpoint;
          let fetchOptions = { method };

          if (method === 'GET') {
            const separator = url.includes('?') ? '&' : '?';
            url = url + separator + encodeURIComponent(paramName) + '=' + encodeURIComponent(payload);
          } else {
            fetchOptions.headers = { 'Content-Type': 'application/json' };
            const bodyObj = {};
            bodyObj[paramName] = payload;
            if (paramName === 'content') bodyObj['author'] = 'Workbench-Tester';
            fetchOptions.body = JSON.stringify(bodyObj);
          }

          const res = await fetch(url, fetchOptions);
          statusEl.textContent = 'Status: ' + res.status + ' ' + res.statusText;

          let headerStr = '';
          for (let [k, v] of res.headers.entries()) {
            headerStr += k + ': ' + v + '\\n';
          }
          headersEl.textContent = headerStr || '(No exposed headers)';

          const text = await res.text();
          bodyEl.textContent = text.slice(0, 3000);

          const containsRawPayload = text.includes(payload);
          if (containsRawPayload && payload.length > 0) {
            verdictEl.style.backgroundColor = 'var(--vuln-bg)';
            verdictEl.style.border = '1px solid var(--vuln-border)';
            verdictEl.style.color = 'var(--vuln-text)';
            verdictEl.innerHTML = '⚠️ <strong>Analysis:</strong> The exact raw input string was found unescaped in the server response body.';
          } else {
            verdictEl.style.backgroundColor = 'var(--sec-bg)';
            verdictEl.style.border = '1px solid var(--sec-border)';
            verdictEl.style.color = 'var(--sec-text)';
            verdictEl.innerHTML = '🛡️ <strong>Analysis:</strong> The raw input string was NOT reflected as raw markup. Output is either entity-encoded or filtered.';
          }
        } catch (err) {
          statusEl.textContent = 'Error';
          bodyEl.textContent = 'Request failed: ' + err.message;
        }
      }
    </script>
  `;

  return renderLayout({
    title: 'Testing Workbench',
    activeNav: 'workbench',
    bodyContent
  });
}
