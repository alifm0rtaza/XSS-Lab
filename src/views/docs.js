import { renderLayout } from '../server/utils.js';

export function renderDocsPage() {
  const bodyContent = `
    <div class="lab-header">
      <div class="lab-title-group">
        <h1>
          Documentation &amp; Learning Guide
          <span class="badge badge-local">Educational Reference</span>
        </h1>
        <p class="lab-subtitle">In-depth technical explanations of Cross-Site Scripting vulnerabilities, contexts, HTTP flows, and remediation</p>
      </div>
    </div>

    <div class="drawer-container" style="gap: 0.85rem;">

      <!-- 1. What is XSS? -->
      <details class="edu-drawer" open>
        <summary>
          <span>1. What is Cross-Site Scripting (XSS)?</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            <strong>Cross-Site Scripting (XSS)</strong> occurs when an application includes untrusted user data in a web page without proper validation, escaping, or context-aware encoding. This allows an attacker to inject client-side script (typically JavaScript) that executes within the victim's browser in the security context of the vulnerable application.
          </p>
          <p>
            Once script execution occurs, the injected code runs with the full privileges of the user's session, allowing the script to read DOM content, interact with APIs on behalf of the user, modify the page UI, or trigger application actions.
          </p>
        </div>
      </details>

      <!-- 2. Reflected XSS -->
      <details class="edu-drawer">
        <summary>
          <span>2. Reflected XSS</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            In <strong>Reflected XSS</strong>, untrusted data from an immediate HTTP request (such as a search query parameter or form submission) is reflected by the server directly into the HTTP response.
          </p>
          <p>
            <strong>Key Data Flow:</strong> <code>User Request (?q=...) ➔ Server Processing ➔ Immediate HTTP Response ➔ Browser Rendering ➔ Execution</code>.
          </p>
          <p>
            Reflected XSS is non-persistent; the injected script executes only when a user visits the specially crafted request link or submits the form.
          </p>
        </div>
      </details>

      <!-- 3. Stored XSS -->
      <details class="edu-drawer">
        <summary>
          <span>3. Stored XSS (Persistent)</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            In <strong>Stored XSS</strong>, untrusted user input is saved permanently by the application into persistent storage (such as a database, JSON file, or message queue).
          </p>
          <p>
            <strong>Key Data Flow:</strong> <code>User POST Request ➔ Server ➔ Persistent Storage (data/messages.json) ➔ Later GET Request ➔ Retrieval ➔ Unescaped Response ➔ Victim Browser Execution</code>.
          </p>
          <p>
            Stored XSS is often higher impact because any user who views the affected page executes the payload automatically without needing to click an attacker-controlled link.
          </p>
        </div>
      </details>

      <!-- 4. DOM-Based XSS -->
      <details class="edu-drawer">
        <summary>
          <span>4. DOM-Based XSS</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            <strong>DOM-Based XSS</strong> occurs entirely in the client-side JavaScript environment. The server's HTTP response may be completely static or clean; the vulnerability arises because client-side JavaScript reads data from a browser <strong>Source</strong> and passes it to an unsafe <strong>Sink</strong>.
          </p>
          <p>
            <strong>Key Data Flow:</strong> <code>Browser Source (location.search / location.hash) ➔ Client Script ➔ Unsafe Sink (innerHTML / document.write) ➔ Browser Interpretation</code>.
          </p>
        </div>
      </details>

      <!-- 5. HTML Contexts -->
      <details class="edu-drawer">
        <summary>
          <span>5. HTML Contexts (Body vs. Attribute)</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            <strong>HTML Body Context:</strong> Input is placed between HTML tags (e.g. <code>&lt;p&gt;Hello USER_INPUT&lt;/p&gt;</code>). Attackers inject new HTML elements (e.g. <code>&lt;script&gt;</code> or <code>&lt;img src=x onerror=...&gt;</code>).
          </p>
          <p>
            <strong>HTML Attribute Context:</strong> Input is placed inside a tag attribute (e.g. <code>&lt;input value="USER_INPUT"&gt;</code>). Attackers use quotes (<code>"</code>) to close the attribute and inject new event handlers (e.g. <code>" onfocus="alert(1)" autofocus="</code>).
          </p>
        </div>
      </details>

      <!-- 6. JavaScript Contexts -->
      <details class="edu-drawer">
        <summary>
          <span>6. JavaScript String Contexts</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            When input is placed inside a JavaScript literal (e.g. <code>&lt;script&gt;var keyword = "USER_INPUT";&lt;/script&gt;</code>), HTML entity encoding is often insufficient. An attacker closes the string literal with matching quotes and semicolons (<code>"; alert(1); //</code>) or breaks out using <code>&lt;/script&gt;</code> tags.
          </p>
          <p>
            <strong>Remediation:</strong> Use safe JSON serialization (<code>JSON.stringify()</code>) and explicitly escape closing script tags (<code>&lt;</code> ➔ <code>\\u003c</code>).
          </p>
        </div>
      </details>

      <!-- 7. URL Contexts -->
      <details class="edu-drawer">
        <summary>
          <span>7. URL / HREF Contexts</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            When input populates a URL-bearing attribute (e.g. <code>&lt;a href="USER_INPUT"&gt;</code>), standard HTML encoding allows the <code>javascript:</code> pseudo-protocol to pass through. When clicked, the browser executes the script in the current page origin.
          </p>
          <p>
            <strong>Remediation:</strong> Enforce strict protocol whitelists allowing only <code>http:</code>, <code>https:</code>, or relative paths.
          </p>
        </div>
      </details>

      <!-- 8. Sources and Sinks -->
      <details class="edu-drawer">
        <summary>
          <span>8. Sources and Sinks</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            <strong>Sources:</strong> Browser properties controlled by the user or navigation:
            <code>window.location.search</code>, <code>window.location.hash</code>, <code>document.referrer</code>, <code>window.name</code>, <code>postMessage</code>.
          </p>
          <p>
            <strong>Sinks:</strong> JavaScript APIs or DOM properties that interpret strings as executable code or HTML:
            <code>element.innerHTML</code>, <code>document.write()</code>, <code>eval()</code>, <code>setTimeout(string)</code>, <code>element.src</code>, <code>element.href</code>.
          </p>
        </div>
      </details>

      <!-- 9. Persistence -->
      <details class="edu-drawer">
        <summary>
          <span>9. Persistence Mechanics</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            In this laboratory, Stored XSS persistence is genuinely backed by server-side disk storage (<code>data/messages.json</code>). Submissions persist across page reloads, browser restarts, and across separate local browser sessions until explicitly reset via <strong>Reset Lab</strong>.
          </p>
        </div>
      </details>

      <!-- 10. Browser Execution -->
      <details class="edu-drawer">
        <summary>
          <span>10. Browser Execution Mechanics</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            This laboratory relies on <strong>genuine browser interpretation</strong>. There is no fake payload detection or hardcoded string matching. When valid syntax reaches the browser's HTML parser or JavaScript runtime, the browser executes the script natively (e.g. displaying a real <code>alert()</code> dialog with your exact supplied message).
          </p>
        </div>
      </details>

      <!-- 11. HTTP Flow -->
      <!-- 11. Core Lab Principle: Reflection vs Injection vs Execution -->
      <details class="edu-drawer">
        <summary>
          <span>11. Crucial Distinction: Reflection ≠ HTML Injection ≠ JavaScript Execution</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            The laboratory strictly enforces the distinction between reflection, injection, and execution:
          </p>
          <ul style="padding-left: 1.25rem; line-height: 1.6;">
            <li><strong>A. Input Accepted:</strong> The server receives an HTTP parameter (e.g. <code>?q=LAB_TEST_123</code>).</li>
            <li><strong>B. Input Reflected:</strong> The server echoes the exact input bytes in the response body. This alone is <em>not</em> an exploit.</li>
            <li><strong>C. HTML Injection:</strong> The input contains HTML tags/attributes (e.g. <code>&lt;b&gt;test&lt;/b&gt;</code>) that the browser parses as new markup rather than text.</li>
            <li><strong>D. JavaScript Execution:</strong> Injected JavaScript code actually triggers and runs within the client browser runtime (e.g. executing an alert dialog or reading document cookies).</li>
          </ul>
        </div>
      </details>

      <!-- 12. HTTP Request & Response Flow -->
      <details class="edu-drawer">
        <summary>
          <span>12. HTTP Request &amp; Response Flow &amp; DevTools Inspection</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            All laboratory modules use standard HTTP semantics and authentic query parameters:
          </p>
          <ul>
            <li><code>GET /reflected/search?q=...</code> — Parameter <code>q</code> processed on server and echoed into response.</li>
            <li><code>GET /reflected/results?search=...</code> — Parameter <code>search</code> processed and echoed.</li>
            <li><code>GET /reflected/profile?name=...</code> — Parameter <code>name</code> processed in profile card.</li>
            <li><code>GET /reflected/message?message=...</code> — Parameter <code>message</code> processed in status banner.</li>
            <li><code>GET /reflected/item?id=...</code> — Parameter <code>id</code> processed in item lookup card.</li>
            <li><code>POST /labs/stored</code> — Form fields stored persistently in JSON datastore (<code>data/messages.json</code>).</li>
            <li><code>GET /labs/stored</code> — Stored records rendered into subsequent HTTP response bodies.</li>
            <li><code>GET /labs/dom?q=...</code> — Static server response processed client-side via JavaScript.</li>
          </ul>
          <p style="margin-top: 0.5rem;">
            Inspect any scenario by opening native <strong>Browser DevTools (F12)</strong>: use the <strong>Network</strong> tab to view query parameters and raw server responses, and the <strong>Elements</strong> tab to inspect the rendered DOM tree.
          </p>
        </div>
      </details>

      <!-- 12. Testing with Burp Suite -->
      <details class="edu-drawer">
        <summary>
          <span>12. Testing with Burp Suite / Intercepting Proxies</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            Because the lab uses standard HTTP traffic bound to <code>127.0.0.1</code>, configuring Burp Suite or OWASP ZAP to proxy local traffic allows full interception of requests, modification of query/POST parameters, and analysis of server response headers.
          </p>
          <p>
            To intercept in Burp Suite: Set proxy listener on <code>127.0.0.1:8080</code> and configure browser proxy settings accordingly.
          </p>
        </div>
      </details>

      <!-- 13. Local Advanced Browser Testing -->
      <details class="edu-drawer">
        <summary>
          <span>13. Why Stored XSS Can Lead to Browser-Side Framework Interaction</span>
          <span>▾</span>
        </summary>
        <div class="drawer-body">
          <p>
            <strong>Underlying Principle:</strong> Stored XSS persists attacker-controlled content on the server. When any victim browser later opens the affected page, the server returns the payload and the browser executes the injected JavaScript within that user's active session origin.
          </p>
          <p>
            An advanced browser-testing framework (such as BeEF) uses JavaScript executed in that victim browser context to establish a communication channel back to the framework's local control listener.
          </p>
          <p>
            <strong>Core Educational Distinction:</strong> Stored XSS is the application vulnerability; BeEF and similar tools are external testing frameworks. Stored XSS exists independently and does not require any specific tool.
          </p>
          <h4 style="margin-top: 0.75rem; font-size: 0.92rem; color: var(--text-main);">Genuine Local BeEF Integration:</h4>
          <p style="margin-top: 0.35rem; line-height: 1.55;">
            The actual laboratory browser communicates directly with the real local BeEF server (e.g. <code>http://127.0.0.1:3001/hook.js</code>). When genuinely hooked, the real browser appears in the official <strong>BeEF Control Panel</strong> under <code>Online Browsers</code>. The laboratory does not simulate fake browsers or intercept BeEF traffic.
          </p>
          <h4 style="margin-top: 0.75rem; font-size: 0.92rem; color: var(--text-main);">Full Lab Restore &amp; Genuine BeEF Session Cleanup:</h4>
          <p style="margin-top: 0.35rem; line-height: 1.55;">
            When executing <strong>Restore Entire Lab</strong>, the laboratory resets all local datastores, clears client storage, and actively communicates with the local BeEF REST API (<code>GET /api/hooks/:session/delete</code>) to terminate and remove the lab-created hooked browser session from BeEF. This ensures BeEF no longer lists the old browser as either <code>Online</code> or <code>Offline</code>, returning the environment to a clean factory baseline.
          </p>
          <h4 style="margin-top: 0.75rem; font-size: 0.92rem; color: var(--text-main);">Local Network Model &amp; Reachability:</h4>
          <ul style="padding-left: 1.25rem; margin-top: 0.35rem;">
            <li><code>127.0.0.1</code> / <code>localhost</code>: Refers strictly to the loopback interface on the local machine. A separate virtual machine or external device cannot connect to <code>127.0.0.1</code> on another host.</li>
            <li><code>LAN IP (e.g. 192.168.x.x)</code>: Required when testing across multiple virtual machines or separate lab devices on the same local subnet.</li>
          </ul>
          <p style="margin-top: 0.5rem;">
            The laboratory is configured by default for <code>127.0.0.1</code> local security training to ensure safety and isolation.
          </p>
        </div>
      </details>

    </div>
  `;

  return renderLayout({
    title: 'Documentation & Learning Guide',
    activeNav: 'documentation',
    bodyContent
  });
}
