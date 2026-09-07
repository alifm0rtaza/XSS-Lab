import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { getMessages, addMessage, resetMessages } from '../storage/messageStore.js';
import { restoreFullLab, getLabStatus } from '../storage/labStore.js';
import { renderHomePage } from '../views/home.js';
import { 
  renderReflectedLab, 
  renderReflectedMainLab, 
  renderReflectedContextsLab, 
  renderReflectedAdvancedLab, 
  renderReflectedParamScenario 
} from '../views/reflected.js';
import { 
  renderStoredLab, 
  renderStoredMainLab, 
  renderStoredContextsLab, 
  renderStoredAdvancedLab 
} from '../views/stored.js';
import { 
  renderDomLab, 
  renderDomMainLab, 
  renderDomSourcesSinksLab, 
  renderDomAdvancedLab 
} from '../views/dom.js';
import { renderWorkbenchPage } from '../views/workbench.js';
import { renderPayloadsPage } from '../views/payloads.js';
import { renderDocsPage } from '../views/docs.js';
import { renderLayout } from './utils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createApp() {
  const app = express();

  // Middleware
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());

  // Static Assets
  app.use('/public', express.static(path.resolve(__dirname, '../public')));

  // ==========================================
  // HOME / OVERVIEW ROUTE
  // ==========================================
  app.get('/', (req, res) => {
    res.send(renderHomePage());
  });

  // ==========================================
  // 1. REFLECTED XSS (3-TIER ARCHITECTURE)
  // ==========================================

  // Tier 1: Main Reflected Lab (Recommended Starting Point)
  app.get(['/labs/reflected/main', '/labs/reflected'], (req, res) => {
    // If context query is explicitly provided on /labs/reflected, preserve context router for backward compatibility
    if (req.query.context && req.path === '/labs/reflected') {
      const query = req.query.q || '';
      return res.send(renderReflectedContextsLab({ isSecure: false, query, context: req.query.context }));
    }
    const query = req.query.q || req.query.search || req.query.name || req.query.message || req.query.id || '';
    const paramName = req.query.param || (req.query.search ? 'search' : req.query.name ? 'name' : req.query.message ? 'message' : req.query.id ? 'id' : 'q');
    const endpoint = req.query.endpoint || '/reflected/search';
    res.send(renderReflectedMainLab({ isSecure: false, query, paramName, endpoint }));
  });

  app.get(['/labs/reflected/main/secure', '/labs/reflected/secure'], (req, res) => {
    if (req.query.context && req.path === '/labs/reflected/secure') {
      const query = req.query.q || '';
      return res.send(renderReflectedContextsLab({ isSecure: true, query, context: req.query.context }));
    }
    const query = req.query.q || req.query.search || req.query.name || req.query.message || req.query.id || '';
    const paramName = req.query.param || (req.query.search ? 'search' : req.query.name ? 'name' : req.query.message ? 'message' : req.query.id ? 'id' : 'q');
    const endpoint = req.query.endpoint || '/reflected/search';
    res.send(renderReflectedMainLab({ isSecure: true, query, paramName, endpoint }));
  });

  // Tier 2: Core Contexts Lab (HTML Body, Attribute, JS String, URL / href)
  app.get('/labs/reflected/contexts', (req, res) => {
    const query = req.query.q || '';
    const context = req.query.context || 'html_body';
    res.send(renderReflectedContextsLab({ isSecure: false, query, context }));
  });

  app.get('/labs/reflected/contexts/secure', (req, res) => {
    const query = req.query.q || '';
    const context = req.query.context || 'html_body';
    res.send(renderReflectedContextsLab({ isSecure: true, query, context }));
  });

  // Tier 3: Advanced Challenges (Filters, Attribute Events, Script Closures, Protocols)
  app.get('/labs/reflected/advanced', (req, res) => {
    const query = req.query.q || '';
    const challenge = req.query.challenge || 'tag_filter';
    res.send(renderReflectedAdvancedLab({ isSecure: false, query, challenge }));
  });

  app.get('/labs/reflected/advanced/secure', (req, res) => {
    const query = req.query.q || '';
    const challenge = req.query.challenge || 'tag_filter';
    res.send(renderReflectedAdvancedLab({ isSecure: true, query, challenge }));
  });

  // ==========================================
  // REAL PARAMETERIZED REFLECTED ENDPOINTS
  // Genuine HTTP routes with authentic parameter handling
  // ==========================================

  // Endpoint 1: /reflected/search?q=...
  app.get('/reflected/search', (req, res) => {
    const q = req.query.q || '';
    res.send(renderReflectedParamScenario({ isSecure: false, endpoint: '/reflected/search', paramName: 'q', inputValue: q }));
  });
  app.get('/reflected/search/secure', (req, res) => {
    const q = req.query.q || '';
    res.send(renderReflectedParamScenario({ isSecure: true, endpoint: '/reflected/search', paramName: 'q', inputValue: q }));
  });

  // Endpoint 2: /reflected/results?search=...
  app.get('/reflected/results', (req, res) => {
    const search = req.query.search || '';
    res.send(renderReflectedParamScenario({ isSecure: false, endpoint: '/reflected/results', paramName: 'search', inputValue: search }));
  });
  app.get('/reflected/results/secure', (req, res) => {
    const search = req.query.search || '';
    res.send(renderReflectedParamScenario({ isSecure: true, endpoint: '/reflected/results', paramName: 'search', inputValue: search }));
  });

  // Endpoint 3: /reflected/profile?name=...
  app.get('/reflected/profile', (req, res) => {
    const name = req.query.name || '';
    res.send(renderReflectedParamScenario({ isSecure: false, endpoint: '/reflected/profile', paramName: 'name', inputValue: name }));
  });
  app.get('/reflected/profile/secure', (req, res) => {
    const name = req.query.name || '';
    res.send(renderReflectedParamScenario({ isSecure: true, endpoint: '/reflected/profile', paramName: 'name', inputValue: name }));
  });

  // Endpoint 4: /reflected/message?message=...
  app.get('/reflected/message', (req, res) => {
    const message = req.query.message || '';
    res.send(renderReflectedParamScenario({ isSecure: false, endpoint: '/reflected/message', paramName: 'message', inputValue: message }));
  });
  app.get('/reflected/message/secure', (req, res) => {
    const message = req.query.message || '';
    res.send(renderReflectedParamScenario({ isSecure: true, endpoint: '/reflected/message', paramName: 'message', inputValue: message }));
  });

  // Endpoint 5: /reflected/item?id=...
  app.get('/reflected/item', (req, res) => {
    const id = req.query.id || '';
    res.send(renderReflectedParamScenario({ isSecure: false, endpoint: '/reflected/item', paramName: 'id', inputValue: id }));
  });
  app.get('/reflected/item/secure', (req, res) => {
    const id = req.query.id || '';
    res.send(renderReflectedParamScenario({ isSecure: true, endpoint: '/reflected/item', paramName: 'id', inputValue: id }));
  });

  // ==========================================
  // 2. STORED XSS (3-TIER ARCHITECTURE)
  // ==========================================
  const isEnvAdvancedEnabled = process.env.BROWSER_EXPLOITATION_LAB_ENABLED === 'true';
  const localLabHost = process.env.LOCAL_LAB_HOST || '127.0.0.1';

  // Tier 1: Main Stored Lab (Two-Session Model)
  app.get(['/labs/stored', '/labs/stored/main'], (req, res) => {
    const messages = getMessages();
    res.send(renderStoredMainLab({ isSecure: false, messages, isAdvanced: isEnvAdvancedEnabled, localLabHost }));
  });

  app.get(['/labs/stored/secure', '/labs/stored/main/secure'], (req, res) => {
    const messages = getMessages();
    res.send(renderStoredMainLab({ isSecure: true, messages, isAdvanced: isEnvAdvancedEnabled, localLabHost }));
  });

  // Tier 2: Core Contexts Lab
  app.get('/labs/stored/contexts', (req, res) => {
    const messages = getMessages();
    res.send(renderStoredContextsLab({ isSecure: false, messages, isAdvanced: isEnvAdvancedEnabled, localLabHost }));
  });

  app.get('/labs/stored/contexts/secure', (req, res) => {
    const messages = getMessages();
    res.send(renderStoredContextsLab({ isSecure: true, messages, isAdvanced: isEnvAdvancedEnabled, localLabHost }));
  });

  // Tier 3: Advanced Stored Lab
  app.get('/labs/stored/advanced', (req, res) => {
    const messages = getMessages();
    res.send(renderStoredAdvancedLab({ isSecure: false, messages, isAdvanced: isEnvAdvancedEnabled, localLabHost }));
  });

  app.get('/labs/stored/advanced/secure', (req, res) => {
    const messages = getMessages();
    res.send(renderStoredAdvancedLab({ isSecure: true, messages, isAdvanced: isEnvAdvancedEnabled, localLabHost }));
  });

  // POST Handlers for Stored Submission
  app.post(['/labs/stored', '/labs/stored/main', '/labs/stored/contexts'], (req, res) => {
    const { author, content, role, website } = req.body;
    if (author || content || role || website) {
      addMessage({ author, content, role, website });
    }
    const redirectUrl = req.path.includes('/main') ? '/labs/stored/main' : req.path.includes('/contexts') ? '/labs/stored/contexts' : '/labs/stored';
    res.redirect(redirectUrl);
  });

  app.post(['/labs/stored/secure', '/labs/stored/main/secure', '/labs/stored/contexts/secure'], (req, res) => {
    const { author, content, role, website } = req.body;
    if (author || content || role || website) {
      addMessage({ author, content, role, website });
    }
    const redirectUrl = req.path.includes('/main') ? '/labs/stored/main/secure' : req.path.includes('/contexts') ? '/labs/stored/contexts/secure' : '/labs/stored/secure';
    res.redirect(redirectUrl);
  });

  // Stored API endpoints
  app.get('/api/stored/messages', (req, res) => {
    const messages = getMessages();
    res.json(messages);
  });

  app.post('/api/stored/messages', (req, res) => {
    const { author, content, role, website } = req.body;
    if (!author && !content && !role && !website) {
      return res.status(400).json({ error: 'Author, content, or profile field required' });
    }
    const message = addMessage({ author, content, role, website });
    res.status(201).json(message);
  });

  app.post('/api/stored/reset', (req, res) => {
    const reset = resetMessages();
    res.json({ success: true, count: reset.length, messages: reset });
  });

  // ==========================================
  // 3. DOM-BASED XSS (3-TIER ARCHITECTURE)
  // ==========================================

  // Tier 1: Main DOM Lab
  app.get(['/labs/dom', '/labs/dom/main'], (req, res) => {
    res.send(renderDomMainLab({ isSecure: false }));
  });

  app.get(['/labs/dom/secure', '/labs/dom/main/secure'], (req, res) => {
    res.send(renderDomMainLab({ isSecure: true }));
  });

  // Tier 2: Core Sources & Sinks Lab
  app.get('/labs/dom/sources-sinks', (req, res) => {
    res.send(renderDomSourcesSinksLab({ isSecure: false }));
  });

  app.get('/labs/dom/sources-sinks/secure', (req, res) => {
    res.send(renderDomSourcesSinksLab({ isSecure: true }));
  });

  // Tier 3: Advanced DOM Challenges
  app.get('/labs/dom/advanced', (req, res) => {
    res.send(renderDomAdvancedLab({ isSecure: false }));
  });

  app.get('/labs/dom/advanced/secure', (req, res) => {
    res.send(renderDomAdvancedLab({ isSecure: true }));
  });

  // ==========================================
  // TESTING WORKBENCH
  // ==========================================
  app.get('/workbench', (req, res) => {
    res.send(renderWorkbenchPage());
  });

  // ==========================================
  // FULL LAB FACTORY RESTORE & STATUS
  // ==========================================
  app.post(['/api/lab/restore', '/api/lab/reset-all'], async (req, res) => {
    const host = req.hostname || '127.0.0.1';
    const result = await restoreFullLab({ labHost: host });
    res.json(result);
  });

  app.get('/api/lab/status', async (req, res) => {
    const host = req.hostname || '127.0.0.1';
    const status = await getLabStatus({ labHost: host });
    res.json(status);
  });

  // ==========================================
  // DOCUMENTATION / LEARNING GUIDE
  // ==========================================
  app.get('/documentation', (req, res) => {
    res.send(renderDocsPage());
  });

  // ==========================================
  // EDUCATIONAL TEST INPUTS / PAYLOAD GUIDE
  // ==========================================
  app.get('/payloads', (req, res) => {
    res.send(renderPayloadsPage());
  });

  // ==========================================
  // 404 Handler
  // ==========================================
  app.use((req, res) => {
    res.status(404).send(renderLayout({
      title: '404 - Page Not Found',
      activeNav: '',
      bodyContent: `
        <div class="playground-card" style="text-align: center; padding: 3rem 1rem;">
          <h1 style="font-size: 2rem; margin-bottom: 0.5rem;">404 - Page Not Found</h1>
          <p style="color: var(--text-muted); margin-bottom: 1.5rem;">The requested lab or resource does not exist.</p>
          <a href="/" class="btn btn-primary">Return to Overview</a>
        </div>
      `
    }));
  });

  return app;
}
