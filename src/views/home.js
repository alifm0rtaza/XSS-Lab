import { renderLayout } from '../server/utils.js';

export function renderHomePage() {
  const bodyContent = `
    <div class="overview-hero">
      <h1>Cross-Site Scripting (XSS) Laboratory</h1>
      <p>
        A realistic, educational web security training environment.
        Explore real HTTP data flows, observable parameter relationships, context breakouts, and browser parsing mechanics.
      </p>
    </div>

    <!-- Reality Badge Callout -->
    <div style="background-color: var(--bg-card-inner); border: 1px solid var(--border-light); border-left: 4px solid var(--accent-primary); border-radius: var(--radius-md); padding: 0.85rem 1rem; margin-bottom: 1.5rem;">
      <div style="font-weight: 700; font-size: 0.95rem; color: var(--text-main); margin-bottom: 0.25rem;">
        🛡️ Core Lab Rule: Reflection &ne; HTML Injection &ne; JavaScript Execution
      </div>
      <p style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.5;">
        Every scenario uses real HTTP parameters (<code>?q=</code>, <code>?search=</code>, <code>?name=</code>, <code>?message=</code>, <code>?id=</code>), authentic server routes, and natural DevTools inspectability. Reflection of input alone is never mislabeled as an exploit.
      </p>
    </div>

    <div style="margin-bottom: 1.25rem;">
      <h2 style="font-size: 1.25rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem;">
        The Three Primary XSS Types:
      </h2>
      <p style="font-size: 0.88rem; color: var(--text-muted);">
        Start with the <strong>Main Lab</strong> for a comprehensive foundation, then dive into <strong>Core Contexts</strong> and <strong>Advanced Challenges</strong>.
      </p>
    </div>

    <div class="lab-grid">
      <!-- Laboratory 1: Reflected XSS -->
      <div class="lab-card">
        <div>
          <div class="lab-card-header">
            <span class="lab-card-number">Type 01</span>
            <span class="badge badge-vuln">Reflected XSS</span>
          </div>
          <h2 class="lab-card-title">Reflected XSS</h2>
          <p class="lab-card-desc">
            Untrusted data sent in the HTTP request is immediately echoed by the server into the HTTP response. Non-persistent and requires user interaction.
          </p>
          <div style="margin-top: 0.75rem; font-size: 0.82rem; color: var(--text-dim);">
            <strong>Real Parameters:</strong> <code>?q=</code>, <code>?search=</code>, <code>?name=</code>, <code>?message=</code>, <code>?id=</code>
          </div>
        </div>

        <div style="margin-top: 1rem; display: flex; flex-direction: column; gap: 0.4rem;">
          <a href="/labs/reflected/main" class="btn btn-primary" style="text-align: center; font-weight: 700;">
            🎯 Main Lab <span style="font-size: 0.72rem; opacity: 0.9; margin-left: 0.3rem;">(Recommended)</span>
          </a>
          <div style="display: flex; gap: 0.4rem;">
            <a href="/labs/reflected/contexts" class="btn btn-secondary" style="flex: 1; text-align: center; font-size: 0.8rem;">🔍 Core Contexts</a>
            <a href="/labs/reflected/advanced" class="btn btn-secondary" style="flex: 1; text-align: center; font-size: 0.8rem;">⚡ Advanced</a>
          </div>
        </div>
      </div>

      <!-- Laboratory 2: Stored XSS -->
      <div class="lab-card">
        <div>
          <div class="lab-card-header">
            <span class="lab-card-number">Type 02</span>
            <span class="badge badge-vuln">Stored XSS</span>
          </div>
          <h2 class="lab-card-title">Stored XSS</h2>
          <p class="lab-card-desc">
            Untrusted data is saved permanently to server storage (<code>data/messages.json</code>) and rendered to subsequent visitors in a Community Board.
          </p>
          <div style="margin-top: 0.75rem; font-size: 0.82rem; color: var(--text-dim);">
            <strong>Mechanism:</strong> Two-Session Model (Author &rarr; Database &rarr; Victim Request)
          </div>
        </div>

        <div style="margin-top: 1rem; display: flex; flex-direction: column; gap: 0.4rem;">
          <a href="/labs/stored/main" class="btn btn-primary" style="text-align: center; font-weight: 700;">
            🎯 Main Lab <span style="font-size: 0.72rem; opacity: 0.9; margin-left: 0.3rem;">(Recommended)</span>
          </a>
          <div style="display: flex; gap: 0.4rem;">
            <a href="/labs/stored/contexts" class="btn btn-secondary" style="flex: 1; text-align: center; font-size: 0.8rem;">🔍 Core Contexts</a>
            <a href="/labs/stored/advanced" class="btn btn-secondary" style="flex: 1; text-align: center; font-size: 0.8rem;">⚡ Advanced</a>
          </div>
        </div>
      </div>

      <!-- Laboratory 3: DOM-based XSS -->
      <div class="lab-card">
        <div>
          <div class="lab-card-header">
            <span class="lab-card-number">Type 03</span>
            <span class="badge badge-vuln">DOM XSS</span>
          </div>
          <h2 class="lab-card-title">DOM-based XSS</h2>
          <p class="lab-card-desc">
            Client JavaScript reads data from browser sources (<code>location.search</code> / <code>#hash</code>) and passes it directly to unsafe DOM sinks.
          </p>
          <div style="margin-top: 0.75rem; font-size: 0.82rem; color: var(--text-dim);">
            <strong>Mechanism:</strong> Client-side execution without server response modification
          </div>
        </div>

        <div style="margin-top: 1rem; display: flex; flex-direction: column; gap: 0.4rem;">
          <a href="/labs/dom/main" class="btn btn-primary" style="text-align: center; font-weight: 700;">
            🎯 Main Lab <span style="font-size: 0.72rem; opacity: 0.9; margin-left: 0.3rem;">(Recommended)</span>
          </a>
          <div style="display: flex; gap: 0.4rem;">
            <a href="/labs/dom/sources-sinks" class="btn btn-secondary" style="flex: 1; text-align: center; font-size: 0.8rem;">🔍 Sources &amp; Sinks</a>
            <a href="/labs/dom/advanced" class="btn btn-secondary" style="flex: 1; text-align: center; font-size: 0.8rem;">⚡ Advanced</a>
          </div>
        </div>
      </div>
    </div>

    <!-- Educational Supporting Tools -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-top: 1.5rem;">
      <div class="playground-card" style="margin-bottom: 0;">
        <h3 style="font-size: 1rem; font-weight: 600; margin-bottom: 0.35rem;">📖 Documentation &amp; Reference</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">In-depth technical guides covering XSS classification, context encoding, source-sink flows, and Burp Suite testing.</p>
        <a href="/documentation" class="btn btn-secondary" style="font-size: 0.82rem;">Read Documentation</a>
      </div>

      <div class="playground-card" style="margin-bottom: 0;">
        <h3 style="font-size: 1rem; font-weight: 600; margin-bottom: 0.35rem;">🧪 Testing Workbench</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">Directly compare raw server HTTP responses versus browser rendered DOM trees across all endpoints.</p>
        <a href="/workbench" class="btn btn-secondary" style="font-size: 0.82rem;">Open Workbench</a>
      </div>

      <div class="playground-card" style="margin-bottom: 0;">
        <h3 style="font-size: 1rem; font-weight: 600; margin-bottom: 0.35rem;">📝 Test Inputs Guide</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">Educational syntax probe examples demonstrating delimiter breakout mechanics for each specific context.</p>
        <a href="/payloads" class="btn btn-secondary" style="font-size: 0.82rem;">View Test Inputs</a>
      </div>
    </div>
  `;

  return renderLayout({
    title: 'Cross-Site Scripting Laboratory',
    activeNav: 'home',
    bodyContent
  });
}
