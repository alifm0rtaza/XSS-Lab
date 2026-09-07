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

test('Testing Workbench Suite - v2', async (t) => {
  const app = createApp();
  const server = http.createServer(app);

  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  t.after(() => {
    server.close();
  });

  await t.test('Workbench page loads successfully with testing matrix', async () => {
    const res = await makeRequest(server, '/workbench');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('Testing Workbench'));
    assert.ok(res.body.includes('Local Endpoint Testing Matrix'));
    assert.ok(res.body.includes('Local Request Dispatcher'));
    assert.ok(res.body.includes('/labs/reflected'));
    assert.ok(res.body.includes('/labs/stored'));
    assert.ok(res.body.includes('/labs/dom'));
  });
});
