import { escapeHtml, renderLayout } from '../server/utils.js';

export function renderPayloadsPage() {
  const sections = [
    {
      category: 'Reflected XSS',
      items: [
        {
          context: 'HTML Body',
          purpose: 'Demonstrates injection directly into the HTML markup body between container tags.',
          example: '<script>alert("XSS TEST EXECUTED")</script>',
          expected: 'Browser HTML parser encounters the script tag in the HTTP response and executes it immediately.',
          link: '/labs/reflected?context=html_body&q=%3Cscript%3Ealert(%22XSS%20TEST%20EXECUTED%22)%3C%2Fscript%3E'
        },
        {
          context: 'HTML Attribute',
          purpose: 'Demonstrates breaking out of tag attributes (e.g. value="...") using quote delimiters.',
          example: '" onfocus="alert(\'XSS TEST EXECUTED\')" autofocus="',
          expected: 'Leading quote closes the attribute; browser attaches and triggers the injected onfocus event.',
          link: '/labs/reflected?context=attribute&q=%22%20onfocus=%22alert(%27XSS%20TEST%20EXECUTED%27)%22%20autofocus=%22'
        },
        {
          context: 'JavaScript String',
          purpose: 'Demonstrates breaking out of JavaScript string literals inside <script> blocks.',
          example: '"; alert("XSS TEST EXECUTED"); //',
          expected: 'Terminates string literal with "; and executes the standalone statement in the JS engine.',
          link: '/labs/reflected?context=javascript&q=%22;%20alert(%22XSS%20TEST%20EXECUTED%22);%20//'
        },
        {
          context: 'URL / HREF',
          purpose: 'Demonstrates executing script when navigating URL-bearing attributes (<a href="...">).',
          example: 'javascript:alert("XSS TEST EXECUTED")',
          expected: 'Browser navigation engine executes the pseudo-protocol script upon click.',
          link: '/labs/reflected?context=url&q=javascript:alert(%22XSS%20TEST%20EXECUTED%22)'
        }
      ]
    },
    {
      category: 'Stored XSS',
      items: [
        {
          context: 'Comment Body',
          purpose: 'Demonstrates permanent storage in data/messages.json and unescaped rendering in subsequent visits.',
          example: '<script>alert("STORED XSS EXECUTED")</script>',
          expected: 'Script executes automatically whenever any user loads the Community Board.',
          link: '/labs/stored'
        },
        {
          context: 'Author & Profile Website',
          purpose: 'Demonstrates multi-field stored injection into author headers and profile website link attributes.',
          example: 'javascript:alert("PROFILE XSS")',
          expected: 'Clicking the stored profile link executes the JavaScript code in the browser.',
          link: '/labs/stored'
        }
      ]
    },
    {
      category: 'DOM-based XSS',
      items: [
        {
          context: 'Query Parameter (location.search)',
          purpose: 'Demonstrates client-side JavaScript reading the URL search string and writing to innerHTML.',
          example: '<img src=x onerror=alert("DOM XSS EXECUTED")>',
          expected: 'Broken image tag triggers the onerror handler immediately upon DOM insertion.',
          link: '/labs/dom?q=%3Cimg%20src=x%20onerror=alert(%22DOM%20XSS%20EXECUTED%22)%3E'
        },
        {
          context: 'URL Fragment (location.hash)',
          purpose: 'Demonstrates browser-only fragment source (never transmitted to server in HTTP requests).',
          example: '<img src=x onerror=alert("DOM HASH EXECUTED")>',
          expected: 'Client-side script extracts hash and parses into innerHTML sink without server reflection.',
          link: '/labs/dom#%3Cimg%20src=x%20onerror=alert(%22DOM%20HASH%20EXECUTED%22)%3E'
        }
      ]
    }
  ];

  const sectionsHtml = sections.map((sec) => {
    const rowsHtml = sec.items.map((item) => `
      <tr>
        <td style="font-weight: 600; white-space: nowrap;">${escapeHtml(item.context)}</td>
        <td style="font-size: 0.85rem; color: var(--text-muted);">${escapeHtml(item.purpose)}</td>
        <td><code style="font-size: 0.8rem; word-break: break-all;">${escapeHtml(item.example)}</code></td>
        <td style="font-size: 0.85rem; color: var(--text-muted);">${escapeHtml(item.expected)}</td>
        <td>
          <a href="${item.link}" class="btn btn-secondary" style="padding: 0.25rem 0.55rem; font-size: 0.75rem; white-space: nowrap;">Open Lab</a>
        </td>
      </tr>
    `).join('');

    return `
      <div class="playground-card" style="margin-bottom: 1.25rem;">
        <h2 style="font-size: 1.15rem; margin-bottom: 0.75rem; color: var(--text-main);">${escapeHtml(sec.category)}</h2>
        <div class="table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Context / Target</th>
                <th>Purpose</th>
                <th>Educational Example</th>
                <th>Expected Behavior</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${rowsHtml}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }).join('');

  const bodyContent = `
    <div class="lab-header">
      <div class="lab-title-group">
        <h1>
          Test Inputs &amp; Context Reference
          <span class="badge badge-local">Educational Reference</span>
        </h1>
        <p class="lab-subtitle">Context-specific analysis of test inputs and syntax breakout requirements</p>
      </div>
    </div>

    <div class="playground-card" style="margin-bottom: 1.25rem;">
      <p style="font-size: 0.9rem; color: var(--text-muted);">
        <strong>Payload Independence:</strong> In this laboratory, vulnerabilities depend on the application's actual data flow and the surrounding syntax context. These examples are teaching aids. You can modify the message text or use any syntactically valid payload suited for the context.
      </p>
    </div>

    ${sectionsHtml}
  `;

  return renderLayout({
    title: 'Test Inputs & Context Reference',
    activeNav: 'payloads',
    bodyContent
  });
}
