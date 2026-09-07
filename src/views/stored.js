import { 
  escapeHtml, 
  escapeHtmlAttr, 
  sanitizeUrl, 
  renderLayout, 
  renderSourceSinkVisualizer,
  renderTierNav,
  renderRealityStatusGrid,
  renderDevToolsGuide
} from '../server/utils.js';

/**
 * 1. MAIN STORED XSS LAB (Recommended Starting Point)
 * Explains persistent lifecycle, database storage (data/messages.json), two-session model, and safe remediation.
 */
export function renderStoredMainLab({ isSecure = false, messages = [], isAdvanced = false, localLabHost = '127.0.0.1' }) {
  const formActionUrl = isSecure ? '/labs/stored/secure' : '/labs/stored';
  const currentLabUrl = isSecure ? '/labs/stored/main/secure' : '/labs/stored/main';

  // Check if any stored message contains active HTML or script
  const hasStoredMessages = messages.length > 0;
  const hasInjectedPayload = messages.some(m => {
    const raw = (m.author || '') + (m.content || '') + (m.role || '') + (m.website || '');
    return raw.includes('<') || raw.includes('>') || raw.toLowerCase().includes('javascript:');
  });

  const visualizerHtml = renderSourceSinkVisualizer({
    source: 'HTTP POST (author, role, website, content)',
    processing: isSecure 
      ? 'Express Server ➔ Persistent File (data/messages.json) ➔ Context-Aware Output Encoding (escapeHtml / sanitizeUrl)' 
      : 'Express Server ➔ Persistent File (data/messages.json) ➔ Direct Unescaped Output Interpolation',
    sink: isSecure ? 'escapeHtml() / sanitizeUrl()' : 'Unsanitized HTML Body & Attribute Interpolation',
    destination: 'Subsequent Visitor Browser DOM',
    isSecure
  });

  const statusGridHtml = renderRealityStatusGrid({
    input: messages.length > 0 ? messages[0].content : '',
    isReflected: false, // It is stored, not simple reflection
    contextName: 'Persistent Database (Multi-Field)',
    isPersistent: true,
    isHtmlInjected: !isSecure && hasInjectedPayload,
    isJsExecuted: false
  });

  let messageListHtml = '';
  if (messages.length === 0) {
    messageListHtml = '<div style="color: var(--text-dim); padding: 0.75rem 0;">No comments in database. Submit a message below to persist it!</div>';
  } else {
    messageListHtml = messages.map((msg) => {
      const authorHtml = isSecure ? escapeHtml(msg.author) : (msg.author || 'Anonymous');
      const roleHtml = isSecure ? escapeHtml(msg.role || 'Member') : (msg.role || 'Member');
      const contentHtml = isSecure ? escapeHtml(msg.content) : (msg.content || '');
      const websiteHref = isSecure ? escapeHtmlAttr(sanitizeUrl(msg.website)) : (msg.website || '#');
      const dateStr = msg.createdAt ? new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent';

      const websiteBadge = msg.website 
        ? `<a href="${websiteHref}" class="msg-link" id="stored-website-link" ${isSecure ? 'target="_blank" rel="noopener noreferrer"' : ''}>Website: ${escapeHtml(msg.website)}</a>`
        : '';

      return `
        <div class="message-item">
          <div class="message-meta">
            <div class="author-group">
              <span class="author-name">👤 ${authorHtml}</span>
              <span class="role-badge">${roleHtml}</span>
            </div>
            <div class="meta-right">
              ${websiteBadge}
              <span style="color: var(--text-dim); font-size: 0.78rem;">${escapeHtml(dateStr)}</span>
            </div>
          </div>
          <div class="message-body">
            ${contentHtml}
          </div>
        </div>
      `;
    }).join('');
  }

  const bodyContent = `
    <!-- Top Header & Mode Switch -->
    <div class="lab-header">
      <div class="lab-title-group">
        <h1>
          Stored Cross-Site Scripting (XSS)
          <span class="badge ${isSecure ? 'badge-secure' : 'badge-vuln'}">${isSecure ? 'Secure Mode' : 'Vulnerable Mode'}</span>
        </h1>
        <p class="lab-subtitle">
          Untrusted input is saved permanently in server storage (<code>data/messages.json</code>) and served to subsequent visitors.
        </p>
      </div>
      <div class="lab-mode-switch">
        <button type="button" class="btn btn-secondary" style="padding: 0.35rem 0.65rem; font-size: 0.8rem; margin-right: 0.35rem;" title="Clears and reseeds the simulated stored-XSS database." onclick="resetStoredMessages('${currentLabUrl}')">🔄 Reset Database</button>
        <a href="/labs/stored/main" class="mode-btn ${!isSecure ? 'active vuln' : ''}">Vulnerable</a>
        <a href="/labs/stored/main/secure" class="mode-btn ${isSecure ? 'active secure' : ''}">Secure</a>
      </div>
    </div>

    <!-- 3-Tier Navigation -->
    ${renderTierNav({ xssType: 'stored', activeTier: 'main', isSecure })}

    <!-- Two-Session Educational Architecture Banner -->
    <div style="background-color: var(--bg-card-inner); border: 1px solid var(--border-light); border-left: 4px solid var(--vuln-primary); border-radius: var(--radius-md); padding: 0.85rem 1rem; margin-bottom: 1.25rem;">
      <div style="font-weight: 700; font-size: 0.92rem; color: var(--text-main); margin-bottom: 0.3rem;">
        👥 The Two-Session Model (Why Stored XSS is Different from Reflected XSS)
      </div>
      <p style="font-size: 0.84rem; color: var(--text-muted); line-height: 1.5;">
        In Reflected XSS, the victim must click an attacker-crafted link containing query parameters (single request). In <strong>Stored XSS</strong>, the attacker posts the payload once (Session A). The server saves it to disk (<code>data/messages.json</code>). Later, any user (Session B) requesting the page receives the payload automatically without clicking any special link.
      </p>
    </div>

    <!-- Main Community Board Card -->
    <div class="playground-card ${isSecure ? 'secure-border' : 'vuln-border'}">
      <div class="card-head-row">
        <div>
          <h2>Community Feedback &bull; Persistent Storage</h2>
          <p style="color: var(--accent-cyan); font-size: 0.88rem; margin-top: 0.2rem;">
            Submit a message below. It is saved to <code>data/messages.json</code> and rendered to all subsequent HTTP requests.
          </p>
        </div>
        <div style="font-family: monospace; font-size: 0.78rem; color: var(--text-dim);">
          <code>Storage: data/messages.json (${messages.length} records)</code>
        </div>
      </div>

      <!-- Submission Form -->
      <form action="${formActionUrl}" method="POST" class="app-form" id="stored-main-form">
        <div class="form-row-grid">
          <div class="form-group">
            <label for="author-input" class="form-label">Author Name (<code>author</code>):</label>
            <input 
              type="text" 
              id="author-input" 
              name="author" 
              class="form-input" 
              placeholder="Your name..." 
              value="Alice"
              required 
              autocomplete="off"
            />
          </div>
          <div class="form-group">
            <label for="role-input" class="form-label">Role / Title (<code>role</code>):</label>
            <input 
              type="text" 
              id="role-input" 
              name="role" 
              class="form-input" 
              placeholder="e.g. Security Analyst" 
              value="Security Analyst"
              autocomplete="off"
            />
          </div>
        </div>

        <div class="form-group">
          <label for="website-input" class="form-label">Website URL (<code>website</code>, Optional):</label>
          <input 
            type="text" 
            id="website-input" 
            name="website" 
            class="form-input" 
            placeholder="e.g. https://example.com or javascript:alert(1)" 
            autocomplete="off"
          />
        </div>

        <div class="form-group">
          <label for="content-input" class="form-label">Comment Content (<code>content</code>):</label>
          <textarea 
            id="content-input" 
            name="content" 
            class="form-textarea" 
            placeholder="Write your comment..." 
            required
          ></textarea>
        </div>

        <div class="btn-group">
          <button type="submit" class="btn ${isSecure ? 'btn-success' : 'btn-primary'}">Post Comment (Persist to Disk)</button>
          <button type="button" class="btn btn-secondary" onclick="useStoredExample('<script>alert(\"STORED XSS EXECUTED\")<\\/script>')">Try XSS Payload</button>
          <button type="button" class="btn btn-secondary" onclick="useStoredExample('<b>Bold Message</b>')">Try HTML Probe</button>
          <button type="button" class="btn btn-secondary" title="Clears and reseeds the simulated stored-XSS database." onclick="resetStoredMessages('${currentLabUrl}')">Reset Database</button>
        </div>
      </form>

      <!-- Persistent Recent Comments Feed -->
      <div class="app-output-section" style="margin-top: 1.25rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 0.5rem;">
          <div style="font-size: 0.95rem; font-weight: 600; color: var(--text-main);">Stored Database Records (${messages.length})</div>
          <div style="font-size: 0.78rem; color: var(--text-dim);">
            Persisted on disk in <code>data/messages.json</code>
          </div>
        </div>
        <div class="message-list">
          ${messageListHtml}
        </div>
      </div>

      <!-- Reality Matrix -->
      <div style="margin-top: 1.25rem;">
        <div style="font-size: 0.88rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem;">
          🔍 Persistent Data Flow &amp; State Matrix:
        </div>
        ${statusGridHtml}
      </div>
    </div>

    <!-- Educational Drawers -->
    <div class="drawer-container">
      <details class="edu-drawer" open>
        <summary>
          <span>💡 Step-by-Step Stored XSS Verification</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <ol style="padding-left: 1.25rem; font-size: 0.85rem; line-height: 1.6; color: var(--text-muted);">
            <li><strong>Step 1 (Submission):</strong> Submit a comment with <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> in this browser tab.</li>
            <li><strong>Step 2 (Persistence Verification):</strong> Inspect the server file <code>data/messages.json</code> to confirm the raw payload is written to persistent storage.</li>
            <li><strong>Step 3 (Victim Simulation):</strong> Open an incognito / private browser window and navigate to <code>http://127.0.0.1:3000/labs/stored</code>.</li>
            <li><strong>Step 4 (Execution):</strong> The new session immediately fetches the stored records and triggers execution automatically without submitting any form or clicking custom query links.</li>
          </ol>
        </div>
      </details>

      <details class="edu-drawer">
        <summary>
          <span>📖 Stored XSS Architecture &amp; Secure Remediation</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            Stored XSS occurs when untrusted data stored in a database or datastore is rendered into an HTML document during subsequent requests without contextual encoding.
          </p>
          <div style="margin-top: 0.75rem;">
            <h4>Stored Data Flow:</h4>
            ${visualizerHtml}
          </div>
          <div style="margin-top: 0.75rem;">
            <h4>Server Retrieval Implementation:</h4>
            <pre class="code-box"><code>${isSecure 
              ? `// SECURE: Context-aware output encoding when rendering stored records\nconst author = escapeHtml(msg.author);\nconst content = escapeHtml(msg.content);\nconst website = sanitizeUrl(msg.website);`
              : `// VULNERABLE: Direct raw interpolation of stored records\nconst author = msg.author;\nconst content = msg.content;\nconst website = msg.website;`}</code></pre>
          </div>
          <div style="margin-top: 0.75rem; background: var(--bg-card-inner); border: 1px solid var(--border-light); border-radius: 4px; padding: 0.65rem 0.85rem; font-size: 0.82rem; color: var(--text-muted);">
            <strong>ℹ️ Two-Tier Reset Architecture:</strong>
            <ul style="padding-left: 1.25rem; margin-top: 0.35rem; line-height: 1.5;">
              <li><strong>Module Reset ("Reset Database"):</strong> Resets only the Stored XSS persistent records in <code>data/messages.json</code> to initial benign seed comments, preventing future page loads from rendering deleted payloads.</li>
              <li><strong>Full Lab Restore ("Restore Entire Lab"):</strong> Completely returns the entire lab to factory state, purging runtime session files, clearing browser storage, and terminating/deleting the lab-created hooked browser session from the local BeEF server via official REST API.</li>
            </ul>
          </div>
        </div>
      </details>
    </div>

    <script>
      function useStoredExample(val) {
        document.getElementById('author-input').value = 'Alice';
        document.getElementById('role-input').value = 'Security Analyst';
        document.getElementById('website-input').value = '';
        const contentInput = document.getElementById('content-input');
        if (contentInput) {
          contentInput.value = val;
          contentInput.focus();
        }
      }

      async function resetStoredMessages(redirectUrl) {
        if (!confirm('Clears and reseeds the simulated stored-XSS database back to initial state?')) return;
        try {
          const res = await fetch('/api/stored/reset', { method: 'POST' });
          if (res.ok) {
            window.location.href = redirectUrl;
          } else {
            alert('Failed to reset stored database.');
          }
        } catch (e) {
          alert('Error: ' + e.message);
        }
      }
    </script>
  `;

  return renderLayout({
    title: 'Stored XSS — Main Lab',
    activeNav: 'stored',
    bodyContent
  });
}

/**
 * 2. CORE CONTEXTS LAB (Stored Community Board)
 */
export function renderStoredContextsLab({ isSecure = false, messages = [], isAdvanced = false, localLabHost = '127.0.0.1' }) {
  return renderStoredMainLab({ isSecure, messages, isAdvanced, localLabHost });
}

/**
 * 3. ADVANCED STORED XSS CHALLENGES
 */
export function renderStoredAdvancedLab({ isSecure = false, messages = [], isAdvanced = false, localLabHost = '127.0.0.1' }) {
  const currentLabUrl = isSecure ? '/labs/stored/advanced/secure' : '/labs/stored/advanced';

  const bodyContent = `
    <!-- Top Header & Mode Switch -->
    <div class="lab-header">
      <div class="lab-title-group">
        <h1>
          Stored XSS — Advanced Challenges
          <span class="badge ${isSecure ? 'badge-secure' : 'badge-vuln'}">${isSecure ? 'Secure' : 'Vulnerable'}</span>
        </h1>
        <p class="lab-subtitle">Multi-field payload chaining, persistent JSON storage breakouts, and cross-session research workflows.</p>
      </div>
      <div class="lab-mode-switch">
        <button type="button" class="btn btn-secondary" style="padding: 0.35rem 0.65rem; font-size: 0.8rem; margin-right: 0.35rem;" onclick="resetStoredMessages('${currentLabUrl}')">🔄 Reset Database</button>
        <a href="/labs/stored/advanced" class="mode-btn ${!isSecure ? 'active vuln' : ''}">Vulnerable</a>
        <a href="/labs/stored/advanced/secure" class="mode-btn ${isSecure ? 'active secure' : ''}">Secure</a>
      </div>
    </div>

    <!-- 3-Tier Navigation -->
    ${renderTierNav({ xssType: 'stored', activeTier: 'advanced', isSecure })}

    <div class="playground-card ${isSecure ? 'secure-border' : 'vuln-border'}">
      <div class="card-head-row">
        <div>
          <h2>Advanced Stored Workflow: Multi-Session Research</h2>
          <p style="color: var(--accent-cyan); font-size: 0.88rem; margin-top: 0.2rem;">
            Test how stored vulnerabilities interact across isolated browser contexts and local testing frameworks.
          </p>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-top: 1rem;">
        <div style="background: var(--bg-card-inner); border: 1px solid var(--border-light); border-radius: var(--radius-md); padding: 1rem;">
          <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.4rem;">1. Multi-Field Payload Split</h3>
          <p style="font-size: 0.82rem; color: var(--text-muted); margin-bottom: 0.75rem;">
            Inject opening tag in Author (<code>&lt;img src=x</code>) and closing handler in Website/Comment (<code>onerror=alert(1)&gt;</code>).
          </p>
          <a href="/labs/stored/main" class="btn btn-secondary" style="font-size: 0.8rem;">Open Multi-Field Form</a>
        </div>

        <div style="background: var(--bg-card-inner); border: 1px solid var(--border-light); border-radius: var(--radius-md); padding: 1rem;">
          <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.4rem;">2. Two-Session Verification</h3>
          <p style="font-size: 0.82rem; color: var(--text-muted); margin-bottom: 0.75rem;">
            Open an incognito/private browser window to verify automatic execution across sessions.
          </p>
          <a href="/labs/stored/main" class="btn btn-secondary" style="font-size: 0.8rem;">Open Stored Main Lab</a>
        </div>

        <div style="background: var(--bg-card-inner); border: 1px solid var(--border-light); border-radius: var(--radius-md); padding: 1rem;">
          <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.4rem;">3. Datastore API Verification</h3>
          <p style="font-size: 0.82rem; color: var(--text-muted); margin-bottom: 0.75rem;">
            Query the raw JSON API endpoint <code>GET /api/stored/messages</code> using curl or fetch.
          </p>
          <a href="/api/stored/messages" target="_blank" class="btn btn-secondary" style="font-size: 0.8rem;">Inspect JSON API</a>
        </div>
      </div>
    </div>

    <script>
      async function resetStoredMessages(redirectUrl) {
        if (!confirm('Clears and reseeds the simulated stored-XSS database back to initial state?')) return;
        try {
          const res = await fetch('/api/stored/reset', { method: 'POST' });
          if (res.ok) {
            window.location.href = redirectUrl;
          } else {
            alert('Failed to reset stored database.');
          }
        } catch (e) {
          alert('Error: ' + e.message);
        }
      }
    </script>
  `;

  return renderLayout({
    title: 'Stored XSS — Advanced Challenges',
    activeNav: 'stored',
    bodyContent
  });
}

/**
 * Universal router for Stored Lab (backward compatible with existing routes & tests)
 */
export function renderStoredLab({ isSecure = false, messages = [], isAdvanced = false, localLabHost = '127.0.0.1', tier = 'main' }) {
  if (tier === 'contexts') {
    return renderStoredContextsLab({ isSecure, messages, isAdvanced, localLabHost });
  }
  if (tier === 'advanced') {
    return renderStoredAdvancedLab({ isSecure, messages, isAdvanced, localLabHost });
  }
  return renderStoredMainLab({ isSecure, messages, isAdvanced, localLabHost });
}
