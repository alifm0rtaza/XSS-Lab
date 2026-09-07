import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/server/app.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_FILE = path.resolve(__dirname, '../data/messages.json');

const BASE_URL = 'http://127.0.0.1:3000';

function fetchUrl(urlPath, method = 'GET', body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, BASE_URL);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method,
      headers: { ...headers }
    };

    if (body) {
      if (typeof body === 'object' && !headers['Content-Type']) {
        options.headers['Content-Type'] = 'application/json';
        body = JSON.stringify(body);
      }
      options.headers['Content-Length'] = Buffer.byteLength(body);
    }

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function runDeepQA() {
  console.log('=== STARTING DEEP QA & FUNCTIONAL VERIFICATION ===\n');

  // Start internal server on port 3000 if not already running
  let server = null;
  try {
    const check = await fetchUrl('/');
  } catch (err) {
    // Server not running, boot it
    const app = createApp();
    server = http.createServer(app);
    await new Promise((resolve) => {
      server.listen(3000, '127.0.0.1', resolve);
    });
    console.log('  [SETUP] Booted local server on 127.0.0.1:3000 for deep QA pass.\n');
  }

  try {
    // 1. Clean Start & Navigation
    console.log('Test 1: Clean Start & Navigation...');
    const homeRes = await fetchUrl('/');
    assert.strictEqual(homeRes.statusCode, 200);
    assert.ok(homeRes.body.includes('XSS <span>LAB</span>') || homeRes.body.includes('XSS LAB'));
    console.log('  [PASS] Homepage loads successfully on 127.0.0.1:3000.\n');

    // 2. Reflected XSS Deep QA
    console.log('Test 2: Reflected XSS Deep QA across all 4 contexts...');
    
    // Context A & C: HTML Body
    const bodyPayload = '<script>alert("body-reflected")</script>';
    const vulnBody = await fetchUrl(`/labs/reflected?context=html_body&q=${encodeURIComponent(bodyPayload)}`);
    assert.ok(vulnBody.body.includes(bodyPayload), 'Vuln Body must contain raw unescaped payload');
    const secBody = await fetchUrl(`/labs/reflected/secure?context=html_body&q=${encodeURIComponent(bodyPayload)}`);
    assert.ok(!secBody.body.includes(bodyPayload), 'Secure Body must not contain raw payload');
    assert.ok(secBody.body.includes('&lt;script&gt;alert(&quot;body-reflected&quot;)&lt;/script&gt;'));
    
    // Verify non-persistence of reflected input
    const subsequentGet = await fetchUrl('/labs/reflected');
    assert.ok(!subsequentGet.body.includes(bodyPayload), 'Reflected input must NOT persist');
    console.log('  [PASS] Context A/C (HTML Body) verified with non-persistence.');

    // Context B & D: Attribute
    const attrPayload = '" onfocus="alert(1)" autofocus="';
    const vulnAttr = await fetchUrl(`/labs/reflected?context=attribute&q=${encodeURIComponent(attrPayload)}`);
    assert.ok(vulnAttr.body.includes(`value="${attrPayload}"`), 'Vuln Attribute must contain unescaped quotes');
    const secAttr = await fetchUrl(`/labs/reflected/secure?context=attribute&q=${encodeURIComponent(attrPayload)}`);
    assert.ok(!secAttr.body.includes(`value="${attrPayload}"`), 'Secure Attribute must escape quotes');
    assert.ok(secAttr.body.includes('&quot; onfocus=&quot;alert(1)&quot; autofocus=&quot;'));
    console.log('  [PASS] Context B/D (HTML Attribute) verified.');

    // Context E: JavaScript String
    const jsPayload = '"; alert("js-context"); //';
    const vulnJs = await fetchUrl(`/labs/reflected?context=javascript&q=${encodeURIComponent(jsPayload)}`);
    assert.ok(vulnJs.body.includes(`var reflectedSearchTerm = "${jsPayload}";`));
    const secJs = await fetchUrl(`/labs/reflected/secure?context=javascript&q=${encodeURIComponent(jsPayload)}`);
    assert.ok(!secJs.body.includes(`"${jsPayload}"`));
    assert.ok(secJs.body.includes(JSON.stringify(jsPayload)));
    console.log('  [PASS] Context E (JavaScript String) verified.');

    // Context F: URL
    const urlPayload = 'javascript:alert("url-context")';
    const vulnUrl = await fetchUrl(`/labs/reflected?context=url&q=${encodeURIComponent(urlPayload)}`);
    assert.ok(vulnUrl.body.includes(`href="${urlPayload}"`));
    const secUrl = await fetchUrl(`/labs/reflected/secure?context=url&q=${encodeURIComponent(urlPayload)}`);
    assert.ok(!secUrl.body.includes(`href="${urlPayload}"`));
    assert.ok(secUrl.body.includes('#blocked-unsafe-protocol'));
    console.log('  [PASS] Context F (URL/href) verified.');

    // Test 2b: 3-Tier Hierarchy & 5 Parameterized Endpoints
    console.log('Test 2b: 3-Tier Hierarchy & 5 Genuine Parameterized Endpoints...');
    const paramsList = [
      { endpoint: '/reflected/search', param: 'q', value: 'DEEP_QA_QUERY_VAL' },
      { endpoint: '/reflected/results', param: 'search', value: 'DEEP_QA_SEARCH_VAL' },
      { endpoint: '/reflected/profile', param: 'name', value: 'DEEP_QA_NAME_VAL' },
      { endpoint: '/reflected/message', param: 'message', value: 'DEEP_QA_MSG_VAL' },
      { endpoint: '/reflected/item', param: 'id', value: 'DEEP_QA_ID_VAL' }
    ];

    for (const p of paramsList) {
      const resp = await fetchUrl(`${p.endpoint}?${p.param}=${encodeURIComponent(p.value)}`);
      assert.strictEqual(resp.statusCode, 200);
      assert.ok(resp.body.includes(p.value), `${p.endpoint} must reflect ?${p.param}= value`);
      assert.ok(resp.body.includes(`?${p.param}=`), `${p.endpoint} must show parameter name ?${p.param}=`);
      assert.ok(resp.body.includes('Reflection Detected'));

      // Secure counterpart
      const secResp = await fetchUrl(`${p.endpoint}/secure?${p.param}=${encodeURIComponent('<script>alert(1)</script>')}`);
      assert.strictEqual(secResp.statusCode, 200);
      assert.ok(secResp.body.includes('&lt;script&gt;'));
      assert.ok(!secResp.body.includes('<script>alert(1)</script>'));
    }

    // Check 3-Tier Main / Contexts / Advanced endpoints
    const mainRef = await fetchUrl('/labs/reflected/main');
    assert.strictEqual(mainRef.statusCode, 200);
    assert.ok(mainRef.body.includes('Main Lab'));

    const ctxRef = await fetchUrl('/labs/reflected/contexts');
    assert.strictEqual(ctxRef.statusCode, 200);
    assert.ok(ctxRef.body.includes('Core Contexts'));

    const advRef = await fetchUrl('/labs/reflected/advanced');
    assert.strictEqual(advRef.statusCode, 200);
    assert.ok(advRef.body.includes('Advanced Challenges'));

    console.log('  [PASS] 3-Tier Hierarchy and all 5 parameterized routes verified.\n');

    // 3. Stored XSS Deep QA
    console.log('Test 3: Stored XSS Deep QA across all fields & persistence...');
    const storedAuthor = '<b onmouseover=alert("author-xss")>Hacker</b>';
    const storedRole = '<em>Chief Admin</em>';
    const storedWebsite = 'javascript:alert("website-xss")';
    const storedContent = '<img src=x onerror=alert("content-xss")>';

    // Submit via POST
    const postBody = new URLSearchParams({
      author: storedAuthor,
      role: storedRole,
      website: storedWebsite,
      content: storedContent
    }).toString();

    const postRes = await fetchUrl('/labs/stored', 'POST', postBody, {
      'Content-Type': 'application/x-www-form-urlencoded'
    });
    assert.strictEqual(postRes.statusCode, 302);

    // Check persistent disk file data/messages.json
    assert.ok(fs.existsSync(DATA_FILE), 'messages.json must exist');
    const diskData = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    const storedEntry = diskData.find(m => m.content === storedContent);
    assert.ok(storedEntry, 'Entry must be persisted in messages.json');
    assert.strictEqual(storedEntry.author, storedAuthor);
    assert.strictEqual(storedEntry.role, storedRole);
    assert.strictEqual(storedEntry.website, storedWebsite);

    // Check vulnerable view renders all fields raw
    const vulnStoredGet = await fetchUrl('/labs/stored');
    assert.ok(vulnStoredGet.body.includes(storedContent), 'Stored content rendered raw');
    assert.ok(vulnStoredGet.body.includes(storedAuthor), 'Stored author rendered raw');
    assert.ok(vulnStoredGet.body.includes(storedRole), 'Stored role rendered raw');
    assert.ok(vulnStoredGet.body.includes(`href="${storedWebsite}"`), 'Stored website link rendered raw');

    // Check secure view escapes all fields and sanitizes website
    const secStoredGet = await fetchUrl('/labs/stored/secure');
    assert.ok(!secStoredGet.body.includes(storedContent), 'Secure stored view must not render raw body');
    assert.ok(!secStoredGet.body.includes(storedAuthor), 'Secure stored view must not render raw author');
    assert.ok(!secStoredGet.body.includes(`href="${storedWebsite}"`), 'Secure stored view must not render raw javascript: link');
    assert.ok(secStoredGet.body.includes('&lt;img src=x onerror=alert(&quot;content-xss&quot;)&gt;'));
    assert.ok(secStoredGet.body.includes('&lt;b onmouseover=alert(&quot;author-xss&quot;)&gt;Hacker&lt;/b&gt;'));
    assert.ok(secStoredGet.body.includes('#blocked-unsafe-protocol'));

    // Reset Storage
    const resetRes = await fetchUrl('/api/stored/reset', 'POST');
    assert.strictEqual(resetRes.statusCode, 200);
    const postResetGet = await fetchUrl('/labs/stored');
    assert.ok(!postResetGet.body.includes(storedContent), 'Payload cleared after reset');
    console.log('  [PASS] Stored XSS (all fields, persistence, JSON storage, reset, vuln vs secure) verified.\n');

    // 4. DOM XSS Deep QA
    console.log('Test 4: DOM XSS Deep QA...');
    const domVulnJs = await fetchUrl('/public/js/dom-vuln.js');
    assert.ok(domVulnJs.body.includes('innerHTML'), 'dom-vuln.js uses innerHTML');
    assert.ok(domVulnJs.body.includes('doc.write'), 'dom-vuln.js uses doc.write');
    assert.ok(domVulnJs.body.includes('linkEl.href'), 'dom-vuln.js uses dynamic href');
    
    const domSecJs = await fetchUrl('/public/js/dom-secure.js');
    assert.ok(domSecJs.body.includes('textContent'), 'dom-secure.js uses textContent');
    assert.ok(domSecJs.body.includes('isSafeUrl'), 'dom-secure.js validates URL protocol');
    console.log('  [PASS] DOM XSS scripts and safe counterparts verified.\n');

    // 5. Source / Sink Visualizers
    console.log('Test 5: Source/Sink Visualizer Component...');
    const refPage = await fetchUrl('/labs/reflected');
    assert.ok(refPage.body.includes('Data Flow'), 'Reflected lab has visualizer');
    assert.ok(refPage.body.includes('flow-step source'));
    const storedPage = await fetchUrl('/labs/stored');
    assert.ok(storedPage.body.includes('Data Flow'), 'Stored lab has visualizer');
    const domPage = await fetchUrl('/labs/dom');
    assert.ok(domPage.body.includes('Data Flow'), 'DOM lab has visualizer');
    console.log('  [PASS] Visualizer diagrams verified across all labs.\n');

    // 6. Testing Workbench
    console.log('Test 6: Testing Workbench...');
    const wbPage = await fetchUrl('/workbench');
    assert.ok(wbPage.body.includes('Local Endpoint Testing Matrix') || wbPage.body.includes('Testing Workbench'));
    assert.ok(wbPage.body.includes('Local Request Dispatcher'));
    console.log('  [PASS] Workbench page and matrix verified.\n');

    // 7. Payloads Guide
    console.log('Test 7: Payloads Guide...');
    const payloadsPage = await fetchUrl('/payloads');
    assert.ok(payloadsPage.body.includes('HTML Body'));
    assert.ok(payloadsPage.body.includes('HTML Attribute'));
    assert.ok(payloadsPage.body.includes('JavaScript String'));
    assert.ok(payloadsPage.body.includes('URL / HREF'));
    console.log('  [PASS] Payloads guide verified.\n');

    // 10. Comprehensive Payload Independence & Test Matrix (A-G)
    console.log('Test 10: Comprehensive Payload Independence Matrix (A-G) across all submodules...');
    
    // Matrix for Reflected Contexts
    const reflectedMatrix = [
      {
        name: 'Reflected HTML Body',
        context: 'html_body',
        example: '<script>alert(document.domain)</script>',
        modified: '<script>console.log("learner-modified-text-99")</script>',
        equivalent: '<img src=x onerror=prompt(123)>',
        harmless: 'Just a normal book title'
      },
      {
        name: 'Reflected HTML Attribute',
        context: 'attribute',
        example: '" onfocus="alert(document.domain)" autofocus="',
        modified: '" onfocus="confirm(\'modified-attribute-text\')" autofocus="',
        equivalent: '" onmouseover="prompt(\'hover-xss\')" data-val="',
        harmless: 'Search keyword 2026'
      },
      {
        name: 'Reflected JavaScript String',
        context: 'javascript',
        example: '"; alert(document.domain); //',
        modified: '"; console.log("learner-modified-js-string"); //',
        equivalent: '</script><script>alert("script-breakout")</script>',
        harmless: 'normal_keyword'
      },
      {
        name: 'Reflected URL / href',
        context: 'url',
        example: 'javascript:alert(document.domain)',
        modified: 'javascript:console.log("learner-modified-url-nav")',
        equivalent: 'javascript:confirm("Click to verify")',
        harmless: 'https://example.com/safe-page'
      }
    ];

    for (const item of reflectedMatrix) {
      // A. Example
      const resA = await fetchUrl(`/labs/reflected?context=${item.context}&q=${encodeURIComponent(item.example)}`);
      assert.ok(resA.body.includes(item.example), `${item.name}: Example payload reflected raw in vuln mode`);

      // B. Modified Example
      const resB = await fetchUrl(`/labs/reflected?context=${item.context}&q=${encodeURIComponent(item.modified)}`);
      assert.ok(resB.body.includes(item.modified), `${item.name}: Modified payload reflected raw in vuln mode without rejection`);

      // C. Equivalent Payload
      const resC = await fetchUrl(`/labs/reflected?context=${item.context}&q=${encodeURIComponent(item.equivalent)}`);
      assert.ok(resC.body.includes(item.equivalent), `${item.name}: Equivalent context payload reflected raw in vuln mode`);

      // D. Harmless input
      const resD = await fetchUrl(`/labs/reflected?context=${item.context}&q=${encodeURIComponent(item.harmless)}`);
      assert.ok(resD.body.includes(item.harmless), `${item.name}: Harmless input reflected cleanly`);

      // E. Reset / Clean state on empty query
      const resE = await fetchUrl(`/labs/reflected?context=${item.context}`);
      assert.ok(!resE.body.includes(item.modified), `${item.name}: Modified input not present in clean state`);

      // F. Secure counterpart escapes in the active rendering sink
      const secA = await fetchUrl(`/labs/reflected/secure?context=${item.context}&q=${encodeURIComponent(item.example)}`);
      if (item.context === 'html_body') {
        assert.ok(!secA.body.includes(`<strong>${item.example}</strong>`), `${item.name}: Body context escaped in secure mode`);
      } else if (item.context === 'attribute') {
        assert.ok(!secA.body.includes(`value="${item.example}"`), `${item.name}: Attribute context escaped in secure mode`);
      } else if (item.context === 'javascript') {
        assert.ok(!secA.body.includes(`var reflectedSearchTerm = "${item.example}"`), `${item.name}: JS string context escaped in secure mode`);
      } else if (item.context === 'url') {
        assert.ok(!secA.body.includes(`href="${item.example}"`), `${item.name}: URL context sanitized in secure mode`);
      }
    }
    console.log('  [PASS] Reflected Submodules (all 4 contexts) passed Payload Independence Matrix.');

    // Matrix for Stored Fields
    const storedFields = [
      { field: 'content', example: '<script>alert(document.domain)</script>', modified: '<script>prompt("custom-stored-text")</script>' },
      { field: 'author', example: '<b onmouseover="alert(document.domain)">Attacker</b>', modified: '<span onclick="console.log(99)">Modified Author</span>' },
      { field: 'role', example: '<em>Admin</em><script>alert(document.domain)</script>', modified: '<strong>Lead Auditor</strong><script>alert("role-99")</script>' },
      { field: 'website', example: 'javascript:alert(document.domain)', modified: 'javascript:confirm("learner-modified-stored-link")' }
    ];

    for (const sf of storedFields) {
      const payloadObj = { author: 'TestUser', role: 'Tester', website: 'https://example.com', content: 'Test comment' };
      payloadObj[sf.field] = sf.modified;

      const postBody = new URLSearchParams(payloadObj).toString();
      await fetchUrl('/labs/stored', 'POST', postBody, { 'Content-Type': 'application/x-www-form-urlencoded' });

      const getRes = await fetchUrl('/labs/stored');
      assert.ok(getRes.body.includes(sf.modified), `Stored field ${sf.field}: Modified payload persisted and retrieved unescaped`);

      // Revisit check
      const revisitRes = await fetchUrl('/labs/stored');
      assert.ok(revisitRes.body.includes(sf.modified), `Stored field ${sf.field}: Modified payload persists on revisit`);
    }

    // Reset storage after matrix run
    await fetchUrl('/api/stored/reset', 'POST');
    const postResetStored = await fetchUrl('/labs/stored');
    assert.ok(!postResetStored.body.includes('learner-modified-stored-link'), 'Stored records clean after reset');
    console.log('  [PASS] Stored Submodules passed Payload Independence Matrix.');

    console.log('  [PASS] All Payload Independence Matrix checks verified.\n');

    console.log('=== ALL DEEP QA CHECKS COMPLETED SUCCESSFULLY ===');
  } finally {
    if (server) {
      server.close();
    }
  }
}

runDeepQA().catch(err => {
  console.error('Deep QA FAILED:', err);
  process.exit(1);
});
