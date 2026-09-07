import test from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import { createApp } from '../src/server/app.js';
import { resetMessages, getMessages } from '../src/storage/messageStore.js';

function makeRequest(server, path, method = 'GET', body = null) {
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
      if (typeof body === 'object') {
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

test('Centered XSS Modal, Database Reset & BeEF Boundary Suite', async (t) => {
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

  await t.test('1. Centered XSS Execution Modal and overlay structure is included in layout', async () => {
    const res = await makeRequest(server, '/');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('id="xss-execution-modal-overlay"'));
    assert.ok(res.body.includes('class="xss-modal-overlay"'));
    assert.ok(res.body.includes('id="xss-modal-title"'));
    assert.ok(res.body.includes('id="xss-modal-ok-btn"'));
    assert.ok(res.body.includes('id="xss-modal-sink"'));
    assert.ok(res.body.includes('id="xss-modal-payload"'));
    assert.ok(res.body.includes('window.closeXssModal'));
    assert.ok(res.body.includes('window.showXssModal'));
  });

  await t.test('2. Stored XSS UI contains "Reset Database" button and explanatory tooltip', async () => {
    const res = await makeRequest(server, '/labs/stored');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('Reset Database'));
    assert.ok(res.body.includes('Clears and reseeds the simulated stored-XSS database'));
  });

  await t.test('3. Reset Database restores seeded messages to initial state', async () => {
    // 1. Add custom stored message
    await makeRequest(server, '/api/stored/messages', 'POST', {
      author: 'Attacker',
      content: '<script>alert(1)</script>'
    });

    // Confirm stored messages length increased
    const msgsBefore = getMessages();
    assert.strictEqual(msgsBefore.length, 3);

    // Call POST /api/stored/reset
    const resetRes = await makeRequest(server, '/api/stored/reset', 'POST');
    assert.strictEqual(resetRes.statusCode, 200);
    const resetJson = JSON.parse(resetRes.body);
    assert.strictEqual(resetJson.success, true);
    assert.strictEqual(resetJson.count, 2);

    // Verify stored messages are back to default seed
    const msgsAfter = getMessages();
    assert.strictEqual(msgsAfter.length, 2);
    assert.strictEqual(msgsAfter[0].author, 'Alice');
  });

  await t.test('4. Global Reset API resets database state cleanly', async () => {
    await makeRequest(server, '/api/stored/messages', 'POST', {
      author: 'GuestUser',
      content: 'Custom comment'
    });

    const resetRes = await makeRequest(server, '/api/lab/reset-all', 'POST');
    assert.strictEqual(resetRes.statusCode, 200);
    const resetJson = JSON.parse(resetRes.body);
    assert.strictEqual(resetJson.success, true);

    const msgs = getMessages();
    assert.strictEqual(msgs.length, 2);
  });

  await t.test('5. External BeEF Boundary: Lab does NOT expose fake hook.js, fake ui/panel, or fake sessions', async () => {
    const hookRes = await makeRequest(server, '/hook.js');
    assert.strictEqual(hookRes.statusCode, 404, 'XSS Lab must NOT expose fake /hook.js');

    const panelRes = await makeRequest(server, '/ui/panel');
    assert.strictEqual(panelRes.statusCode, 404, 'XSS Lab must NOT expose fake /ui/panel');

    const sessionRes = await makeRequest(server, '/testing/browser-session');
    assert.strictEqual(sessionRes.statusCode, 404, 'XSS Lab must NOT expose fake browser session page');

    const telemetryRes = await makeRequest(server, '/telemetry');
    assert.strictEqual(telemetryRes.statusCode, 404, 'XSS Lab must NOT expose fake telemetry page');
  });
});
