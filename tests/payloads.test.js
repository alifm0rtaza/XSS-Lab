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

test('Educational Test Inputs Guide Suite - v2', async (t) => {
  const app = createApp();
  const server = http.createServer(app);

  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  t.after(() => {
    server.close();
  });

  await t.test('Payloads guide page loads successfully with categorized sections', async () => {
    const res = await makeRequest(server, '/payloads');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('Test Inputs'));
    assert.ok(res.body.includes('HTML Body'));
    assert.ok(res.body.includes('HTML Attribute'));
    assert.ok(res.body.includes('JavaScript String'));
    assert.ok(res.body.includes('URL / HREF'));
  });
});
