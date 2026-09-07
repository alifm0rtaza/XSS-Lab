import test from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import { createApp } from '../src/server/app.js';

function makeRequest(server, path, method = 'GET') {
  return new Promise((resolve, reject) => {
    const address = server.address();
    const options = {
      hostname: '127.0.0.1',
      port: address.port,
      path: path,
      method: method
    };

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
    req.end();
  });
}

test('DOM XSS Lab and Static Assets Suite - v2', async (t) => {
  const app = createApp();
  const server = http.createServer(app);

  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  t.after(() => {
    server.close();
  });

  await t.test('DOM XSS (Vulnerable) serves page referencing dom-vuln.js and 3 scenarios', async () => {
    const res = await makeRequest(server, '/labs/dom');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('DOM-based XSS'));
    assert.ok(res.body.includes('Vulnerable'));
    assert.ok(res.body.includes('/public/js/dom-vuln.js'));
    assert.ok(res.body.includes('URL Query Parameter'));
    assert.ok(res.body.includes('URL Fragment'));
    assert.ok(res.body.includes('Additional Sinks'));
  });

  await t.test('DOM XSS (Secure) serves page referencing dom-secure.js and safe remediation notes', async () => {
    const res = await makeRequest(server, '/labs/dom/secure');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('DOM-based XSS'));
    assert.ok(res.body.includes('Secure'));
    assert.ok(res.body.includes('/public/js/dom-secure.js'));
  });

  await t.test('Static assets are correctly served', async () => {
    const cssRes = await makeRequest(server, '/public/css/style.css');
    assert.strictEqual(cssRes.statusCode, 200);
    assert.ok(cssRes.headers['content-type'].includes('text/css'));

    const vulnJsRes = await makeRequest(server, '/public/js/dom-vuln.js');
    assert.strictEqual(vulnJsRes.statusCode, 200);
    assert.ok(vulnJsRes.body.includes('innerHTML'));
    assert.ok(vulnJsRes.body.includes('doc.write'));
    assert.ok(vulnJsRes.body.includes('linkEl.href'));
    assert.ok(vulnJsRes.body.includes('__attachFrameDetector'));

    const secJsRes = await makeRequest(server, '/public/js/dom-secure.js');
    assert.strictEqual(secJsRes.statusCode, 200);
    assert.ok(secJsRes.body.includes('textContent'));
    assert.ok(secJsRes.body.includes('isSafeUrl'));
  });

  await t.test('DOM Source and Sink Mechanics: Script structure verification', async () => {
    const vulnScript = await makeRequest(server, '/public/js/dom-vuln.js');
    assert.ok(vulnScript.body.includes('updateScenario1'), 'Handles query source');
    assert.ok(vulnScript.body.includes('updateFragmentScenario'), 'Handles fragment source');
    assert.ok(vulnScript.body.includes('updateScenario2'), 'Handles document.write sink');
    assert.ok(vulnScript.body.includes('updateScenario3'), 'Handles element.href sink');
  });

  await t.test('Non-existent route returns 404', async () => {
    const res = await makeRequest(server, '/non-existent-endpoint');
    assert.strictEqual(res.statusCode, 404);
    assert.ok(res.body.includes('404 - Page Not Found'));
  });
});
