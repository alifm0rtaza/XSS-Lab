import test from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import { createApp } from '../src/server/app.js';

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

test('Reflected XSS Lab Suite - v2 Expanded Contexts & Reality Patch', async (t) => {
  const app = createApp();
  const server = http.createServer(app);

  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  t.after(() => {
    server.close();
  });

  await t.test('Homepage loads with 3-tier hierarchy for Reflected, Stored, and DOM XSS', async () => {
    const res = await makeRequest(server, '/');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('XSS') && res.body.includes('LAB'), 'Homepage contains brand header');
    assert.ok(res.body.includes('/labs/reflected/main'), 'Contains Reflected Main lab link');
    assert.ok(res.body.includes('/labs/stored/main'), 'Contains Stored Main lab link');
    assert.ok(res.body.includes('/labs/dom/main'), 'Contains DOM Main lab link');
    assert.ok(res.body.includes('/labs/reflected/contexts'), 'Contains Reflected Core Contexts link');
    assert.ok(res.body.includes('/labs/reflected/advanced'), 'Contains Reflected Advanced link');
  });

  await t.test('Main Reflected Lab renders with 3-tier navigation, parameter switcher, and reality matrix', async () => {
    const res = await makeRequest(server, '/labs/reflected/main?q=LAB_TEST_123');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('Reflected Cross-Site Scripting'));
    assert.ok(res.body.includes('Main Lab'));
    assert.ok(res.body.includes('Reflection Detected'));
    assert.ok(res.body.includes('Output Context'));
    assert.ok(res.body.includes('Persistent on Server'));
    assert.ok(res.body.includes('HTML Injection'));
    assert.ok(res.body.includes('JavaScript Execution'));
    assert.ok(res.body.includes('LAB_TEST_123'));
  });

  await t.test('Reality State Separation: Reflection != HTML Injection != JavaScript Execution', async () => {
    // Case 1: Plain alphanumeric text -> Reflection: YES, HTML Injected: NO
    const benignRes = await makeRequest(server, '/labs/reflected/main?q=LAB_TEST_123');
    assert.ok(benignRes.body.includes('LAB_TEST_123'));
    assert.ok(benignRes.body.includes('Reflection Detected'));
    assert.ok(benignRes.body.includes('YES')); // Reflection YES
    assert.ok(benignRes.body.includes('Server response contains user input'));

    // Case 2: HTML Probe -> Reflection: YES, HTML Injected: YES (parsed markup)
    const probeRes = await makeRequest(server, '/labs/reflected/main?q=<b>PROBE_HTML</b>');
    assert.ok(probeRes.body.includes('<b>PROBE_HTML</b>'));
    assert.ok(probeRes.body.includes('Input parsed as live markup'));

    // Case 3: Script Tag -> Reflection: YES, HTML Injected: YES
    const scriptRes = await makeRequest(server, '/labs/reflected/main?q=<script>alert(1)</script>');
    assert.ok(scriptRes.body.includes('<script>alert(1)</script>'));

    // Case 4: Secure counterpart -> Reflection: YES, HTML Injected: NO (Entity Encoded)
    const secureRes = await makeRequest(server, '/labs/reflected/main/secure?q=<script>alert(1)</script>');
    assert.ok(secureRes.body.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    assert.ok(!secureRes.body.includes('<script>alert(1)</script>'));
  });

  await t.test('Genuine Parameterized Endpoints: All 5 parameters processed genuinely by Express', async () => {
    // 1. /reflected/search?q=...
    const resQ = await makeRequest(server, '/reflected/search?q=TEST_PARAM_Q');
    assert.strictEqual(resQ.statusCode, 200);
    assert.ok(resQ.body.includes('TEST_PARAM_Q'));
    assert.ok(resQ.body.includes('?q='));

    // 2. /reflected/results?search=...
    const resSearch = await makeRequest(server, '/reflected/results?search=TEST_PARAM_SEARCH');
    assert.strictEqual(resSearch.statusCode, 200);
    assert.ok(resSearch.body.includes('TEST_PARAM_SEARCH'));
    assert.ok(resSearch.body.includes('?search='));

    // 3. /reflected/profile?name=...
    const resName = await makeRequest(server, '/reflected/profile?name=TEST_PARAM_NAME');
    assert.strictEqual(resName.statusCode, 200);
    assert.ok(resName.body.includes('TEST_PARAM_NAME'));
    assert.ok(resName.body.includes('?name='));

    // 4. /reflected/message?message=...
    const resMsg = await makeRequest(server, '/reflected/message?message=TEST_PARAM_MSG');
    assert.strictEqual(resMsg.statusCode, 200);
    assert.ok(resMsg.body.includes('TEST_PARAM_MSG'));
    assert.ok(resMsg.body.includes('?message='));

    // 5. /reflected/item?id=...
    const resId = await makeRequest(server, '/reflected/item?id=TEST_PARAM_ID');
    assert.strictEqual(resId.statusCode, 200);
    assert.ok(resId.body.includes('TEST_PARAM_ID'));
    assert.ok(resId.body.includes('?id='));
  });

  await t.test('Secure parameterized counterparts correctly sanitize input across all 5 parameters', async () => {
    const payload = '<script>alert("safe")</script>';

    const secQ = await makeRequest(server, `/reflected/search/secure?q=${encodeURIComponent(payload)}`);
    assert.ok(secQ.body.includes('&lt;script&gt;'));
    assert.ok(!secQ.body.includes(payload));

    const secSearch = await makeRequest(server, `/reflected/results/secure?search=${encodeURIComponent(payload)}`);
    assert.ok(secSearch.body.includes('&lt;script&gt;'));
    assert.ok(!secSearch.body.includes(payload));

    const secName = await makeRequest(server, `/reflected/profile/secure?name=${encodeURIComponent(payload)}`);
    assert.ok(secName.body.includes('&lt;script&gt;'));
    assert.ok(!secName.body.includes(payload));

    const secMsg = await makeRequest(server, `/reflected/message/secure?message=${encodeURIComponent(payload)}`);
    assert.ok(secMsg.body.includes('&lt;script&gt;'));
    assert.ok(!secMsg.body.includes(payload));

    const secId = await makeRequest(server, `/reflected/item/secure?id=${encodeURIComponent(payload)}`);
    assert.ok(secId.body.includes('&lt;script&gt;'));
    assert.ok(!secId.body.includes(payload));
  });

  await t.test('Non-persistence verification: Reflected XSS does NOT persist to subsequent requests', async () => {
    // 1. Submit attack payload
    const attackRes = await makeRequest(server, `/reflected/search?q=${encodeURIComponent('<script>alert("temp")</script>')}`);
    assert.ok(attackRes.body.includes('<script>alert("temp")</script>'));

    // 2. Immediate subsequent clean request without parameters contains NO injected payload
    const cleanRes = await makeRequest(server, '/reflected/search');
    assert.ok(!cleanRes.body.includes('<script>alert("temp")</script>'));
    assert.ok(cleanRes.body.includes('Submit input above to view server reflection') || cleanRes.body.includes('No parameter submitted yet'));
  });

  await t.test('Core Contexts Lab: HTML Body Context', async () => {
    const payload = '<script>alert("reflected-body")</script>';
    const vulnRes = await makeRequest(server, `/labs/reflected/contexts?context=html_body&q=${encodeURIComponent(payload)}`);
    assert.strictEqual(vulnRes.statusCode, 200);
    assert.ok(vulnRes.body.includes(payload), 'Payload should be reflected unescaped in vulnerable mode');

    const secRes = await makeRequest(server, `/labs/reflected/contexts/secure?context=html_body&q=${encodeURIComponent(payload)}`);
    assert.strictEqual(secRes.statusCode, 200);
    assert.ok(!secRes.body.includes(payload), 'Raw payload must NOT be present in secure mode');
    assert.ok(secRes.body.includes('&lt;script&gt;alert(&quot;reflected-body&quot;)&lt;/script&gt;'));
  });

  await t.test('Core Contexts Lab: HTML Attribute Context', async () => {
    const payload = '" onfocus="alert(1)" autofocus="';
    
    // Vulnerable
    const vulnRes = await makeRequest(server, `/labs/reflected/contexts?context=attribute&q=${encodeURIComponent(payload)}`);
    assert.strictEqual(vulnRes.statusCode, 200);
    assert.ok(vulnRes.body.includes(`value="${payload}"`), 'Unescaped quotes allowed in attribute');

    // Secure
    const secRes = await makeRequest(server, `/labs/reflected/contexts/secure?context=attribute&q=${encodeURIComponent(payload)}`);
    assert.strictEqual(secRes.statusCode, 200);
    assert.ok(!secRes.body.includes(`value="${payload}"`), 'Quotes must be escaped in attribute value');
    assert.ok(secRes.body.includes('&quot; onfocus=&quot;alert(1)&quot; autofocus=&quot;'));
  });

  await t.test('Core Contexts Lab: JS String Context', async () => {
    const payload = '"; alert(1); //';
    
    // Vulnerable
    const vulnRes = await makeRequest(server, `/labs/reflected/contexts?context=javascript&q=${encodeURIComponent(payload)}`);
    assert.strictEqual(vulnRes.statusCode, 200);
    assert.ok(vulnRes.body.includes(`var reflectedSearchTerm = "${payload}";`));

    // Secure
    const secRes = await makeRequest(server, `/labs/reflected/contexts/secure?context=javascript&q=${encodeURIComponent(payload)}`);
    assert.strictEqual(secRes.statusCode, 200);
    assert.ok(!secRes.body.includes(`"${payload}"`), 'Raw string concatenation avoided in JS block');
    assert.ok(secRes.body.includes(JSON.stringify(payload)));
  });

  await t.test('Core Contexts Lab: URL Context', async () => {
    const payload = 'javascript:alert(1)';
    
    // Vulnerable
    const vulnRes = await makeRequest(server, `/labs/reflected/contexts?context=url&q=${encodeURIComponent(payload)}`);
    assert.strictEqual(vulnRes.statusCode, 200);
    assert.ok(vulnRes.body.includes(`href="${payload}"`), 'Unsafe javascript: protocol allowed');

    // Secure
    const secRes = await makeRequest(server, `/labs/reflected/contexts/secure?context=url&q=${encodeURIComponent(payload)}`);
    assert.strictEqual(secRes.statusCode, 200);
    assert.ok(!secRes.body.includes(`href="${payload}"`), 'Unsafe javascript: protocol blocked');
    assert.ok(secRes.body.includes('#blocked-unsafe-protocol'));
  });

  await t.test('Advanced Challenges: Blacklist filter bypass & Attribute events', async () => {
    const filterRes = await makeRequest(server, `/labs/reflected/advanced?challenge=tag_filter&q=${encodeURIComponent('<SCRIPT>alert(1)</SCRIPT>')}`);
    assert.strictEqual(filterRes.statusCode, 200);
    assert.ok(filterRes.body.includes('<SCRIPT>alert(1)</SCRIPT>'), 'Case variation bypasses naive tag filter');

    const attrRes = await makeRequest(server, `/labs/reflected/advanced?challenge=attr_event&q=${encodeURIComponent('x onfocus=alert(1) autofocus')}`);
    assert.strictEqual(attrRes.statusCode, 200);
    assert.ok(attrRes.body.includes('data-filter="x onfocus=alert(1) autofocus"'));
  });

  await t.test('Payload-Independence: Modified user inputs execute according to context syntax (not hardcoded matches)', async () => {
    // 1. Modified HTML body payloads
    const customBodyPayload1 = '<svg onload=console.log("custom-svg-xss")>';
    const customBodyPayload2 = '<img src=invalid onerror=prompt("Enter credentials")>';
    const res1 = await makeRequest(server, `/labs/reflected?context=html_body&q=${encodeURIComponent(customBodyPayload1)}`);
    assert.ok(res1.body.includes(customBodyPayload1), 'Custom SVG payload must be rendered raw');
    const res2 = await makeRequest(server, `/labs/reflected?context=html_body&q=${encodeURIComponent(customBodyPayload2)}`);
    assert.ok(res2.body.includes(customBodyPayload2), 'Custom IMG prompt payload must be rendered raw');

    // 2. Modified Attribute breakout payloads
    const customAttrPayload = '" onmouseover="confirm(\'modified-attr\')" data-x="';
    const attrRes = await makeRequest(server, `/labs/reflected?context=attribute&q=${encodeURIComponent(customAttrPayload)}`);
    assert.ok(attrRes.body.includes(`value="${customAttrPayload}"`), 'Modified attribute payload must break out of quotes');

    // 3. Modified JavaScript string breakouts
    const customJsPayload1 = '"; window.testVar = 42; //';
    const customJsPayload2 = '</script><script>console.log("breakout")</script>';
    const jsRes1 = await makeRequest(server, `/labs/reflected?context=javascript&q=${encodeURIComponent(customJsPayload1)}`);
    assert.ok(jsRes1.body.includes(`var reflectedSearchTerm = "${customJsPayload1}";`));
    const jsRes2 = await makeRequest(server, `/labs/reflected?context=javascript&q=${encodeURIComponent(customJsPayload2)}`);
    assert.ok(jsRes2.body.includes(customJsPayload2));

    // 4. Modified URL protocol payloads
    const customUrlPayload = 'javascript:confirm("Click navigation confirmed")';
    const urlRes = await makeRequest(server, `/labs/reflected?context=url&q=${encodeURIComponent(customUrlPayload)}`);
    assert.ok(urlRes.body.includes(`href="${customUrlPayload}"`));

    // 5. Harmless input renders safely without crashing or unexpected transformation
    const harmless = 'Normal search query 123!';
    const harmlessRes = await makeRequest(server, `/labs/reflected?context=html_body&q=${encodeURIComponent(harmless)}`);
    assert.ok(harmlessRes.body.includes(`<strong>${harmless}</strong>`));
  });
});
