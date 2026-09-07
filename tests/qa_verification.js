import test from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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

import { createApp } from '../src/server/app.js';

test('Comprehensive QA Verification Pass on Live Server (127.0.0.1:3000) - v2', async (t) => {
  let server = null;
  try {
    await fetchUrl('/');
  } catch (err) {
    const app = createApp();
    server = http.createServer(app);
    await new Promise((resolve) => {
      server.listen(3000, '127.0.0.1', resolve);
    });
  }

  t.after(() => {
    if (server) server.close();
  });

  await t.test('1. Check Server Response and Host Binding', async () => {
    const res = await fetchUrl('/');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('XSS') && res.body.includes('LAB'), 'Homepage title rendered');
    assert.ok(res.body.includes('Local Security Lab') || res.body.includes('Local Only'), 'Badge rendered');
  });

  await t.test('2. Verify All Navigation and Lab Links', async () => {
    const pages = [
      '/',
      '/labs/reflected',
      '/labs/reflected/secure',
      '/labs/reflected?context=attribute',
      '/labs/reflected/secure?context=attribute',
      '/labs/reflected?context=javascript',
      '/labs/reflected/secure?context=javascript',
      '/labs/reflected?context=url',
      '/labs/reflected/secure?context=url',
      '/labs/stored',
      '/labs/stored/secure',
      '/labs/dom',
      '/labs/dom/secure',
      '/workbench',
      '/documentation',
      '/payloads',
      '/public/css/style.css',
      '/public/js/dom-vuln.js',
      '/public/js/dom-secure.js'
    ];

    for (const page of pages) {
      const res = await fetchUrl(page);
      assert.strictEqual(res.statusCode, 200, `Page ${page} should return 200 OK`);
      assert.ok(res.body.length > 0, `Page ${page} should return non-empty content`);
    }
  });

  await t.test('3. Verify Reflected XSS Data-Flow: All Contexts', async () => {
    const testPayload = '<img src=x onerror=alert("qa-reflected")>';

    // Body context
    const vulnRes = await fetchUrl(`/labs/reflected?q=${encodeURIComponent(testPayload)}`);
    assert.strictEqual(vulnRes.statusCode, 200);
    assert.ok(vulnRes.body.includes(testPayload), 'Vulnerable reflected lab outputs raw HTML');

    const secRes = await fetchUrl(`/labs/reflected/secure?q=${encodeURIComponent(testPayload)}`);
    assert.strictEqual(secRes.statusCode, 200);
    assert.ok(!secRes.body.includes(testPayload), 'Secure reflected lab must NOT output raw payload');
    assert.ok(secRes.body.includes('&lt;img src=x onerror=alert(&quot;qa-reflected&quot;)&gt;'));

    // Attribute context
    const attrPayload = '" onfocus="alert(1)" autofocus="';
    const vulnAttr = await fetchUrl(`/labs/reflected?context=attribute&q=${encodeURIComponent(attrPayload)}`);
    assert.ok(vulnAttr.body.includes(`value="${attrPayload}"`));
    const secAttr = await fetchUrl(`/labs/reflected/secure?context=attribute&q=${encodeURIComponent(attrPayload)}`);
    assert.ok(!secAttr.body.includes(`value="${attrPayload}"`));

    // URL context
    const urlPayload = 'javascript:alert(1)';
    const vulnUrl = await fetchUrl(`/labs/reflected?context=url&q=${encodeURIComponent(urlPayload)}`);
    assert.ok(vulnUrl.body.includes(`href="${urlPayload}"`));
    const secUrl = await fetchUrl(`/labs/reflected/secure?context=url&q=${encodeURIComponent(urlPayload)}`);
    assert.ok(secUrl.body.includes('#blocked-unsafe-protocol'));
  });

  await t.test('4. Verify Stored XSS: Multi-Field Submission, Rendering, and Reset', async () => {
    const storedPayload = '<svg onload=alert("qa-stored")>';
    const storedAuthor = '<b onmouseover=alert(1)>QA-Author</b>';
    const storedWebsite = 'javascript:alert("stored-qa-link")';

    // Submit message via form POST
    const postBody = new URLSearchParams({
      author: storedAuthor,
      role: 'QA Lead',
      website: storedWebsite,
      content: storedPayload
    }).toString();

    const postRes = await fetchUrl('/labs/stored', 'POST', postBody, {
      'Content-Type': 'application/x-www-form-urlencoded'
    });
    assert.strictEqual(postRes.statusCode, 302);
    assert.strictEqual(postRes.headers.location, '/labs/stored');

    // Retrieve vulnerable lab page and check raw injection
    const getVulnRes = await fetchUrl('/labs/stored');
    assert.strictEqual(getVulnRes.statusCode, 200);
    assert.ok(getVulnRes.body.includes(storedPayload), 'Stored body rendered raw');
    assert.ok(getVulnRes.body.includes(storedAuthor), 'Stored author rendered raw');
    assert.ok(getVulnRes.body.includes(`href="${storedWebsite}"`), 'Stored website link rendered raw');

    // Retrieve secure lab page and check safe encoding
    const getSecRes = await fetchUrl('/labs/stored/secure');
    assert.strictEqual(getSecRes.statusCode, 200);
    assert.ok(!getSecRes.body.includes(storedPayload), 'Secure view must not render raw payload');
    assert.ok(getSecRes.body.includes('&lt;svg onload=alert(&quot;qa-stored&quot;)&gt;'));
    assert.ok(getSecRes.body.includes('&lt;b onmouseover=alert(1)&gt;QA-Author&lt;/b&gt;'));
    assert.ok(getSecRes.body.includes('#blocked-unsafe-protocol'));

    // Reset storage via API
    const resetRes = await fetchUrl('/api/stored/reset', 'POST');
    assert.strictEqual(resetRes.statusCode, 200);
    const resetJson = JSON.parse(resetRes.body);
    assert.strictEqual(resetJson.success, true);

    // Verify after reset, payload is gone
    const postResetRes = await fetchUrl('/labs/stored');
    assert.ok(!postResetRes.body.includes(storedPayload), 'Payload must be cleared after reset');
  });

  await t.test('5. Verify DOM XSS Scripts: Source & Sink Mechanics', async () => {
    const vulnScriptRes = await fetchUrl('/public/js/dom-vuln.js');
    assert.strictEqual(vulnScriptRes.statusCode, 200);
    assert.ok(vulnScriptRes.body.includes('innerHTML'), 'Vuln script uses innerHTML sink');
    assert.ok(vulnScriptRes.body.includes('doc.write'), 'Vuln script uses doc.write stream sink');
    assert.ok(vulnScriptRes.body.includes('linkEl.href'), 'Vuln script uses dynamic href sink');

    const secScriptRes = await fetchUrl('/public/js/dom-secure.js');
    assert.strictEqual(secScriptRes.statusCode, 200);
    assert.ok(secScriptRes.body.includes('textContent'), 'Secure script uses textContent safe sink');
    assert.ok(secScriptRes.body.includes('isSafeUrl'), 'Secure script checks safe URLs');
  });

  await t.test('6. Verify Storage File Integrity & Persistence Format', async () => {
    assert.ok(fs.existsSync(DATA_FILE), 'messages.json exists on disk');
    const content = fs.readFileSync(DATA_FILE, 'utf8');
    const parsed = JSON.parse(content);
    assert.ok(Array.isArray(parsed), 'Storage contains a JSON array');
    assert.ok(parsed.length >= 2, 'Default seed records are preserved');
    assert.ok(parsed[0].id && parsed[0].author && parsed[0].content && parsed[0].createdAt);
  });

  await t.test('7. Verify Full Lab Factory Restore & Status Workflow', async () => {
    // 1. Post custom message
    const addRes = await fetchUrl('/api/stored/messages', 'POST', JSON.stringify({
      author: 'QA Lead',
      content: 'Custom verification comment'
    }), { 'Content-Type': 'application/json' });
    assert.strictEqual(addRes.statusCode, 201);

    // 2. Query status
    const statusRes = await fetchUrl('/api/lab/status');
    assert.strictEqual(statusRes.statusCode, 200);
    const statusData = JSON.parse(statusRes.body);
    assert.strictEqual(statusData.online, true);

    // 3. Full Factory Restore
    const restoreRes = await fetchUrl('/api/lab/restore', 'POST');
    assert.strictEqual(restoreRes.statusCode, 200);
    const restoreData = JSON.parse(restoreRes.body);
    assert.strictEqual(restoreData.success, true);
    assert.strictEqual(restoreData.storage.messagesCount, 2);
  });
});
