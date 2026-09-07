import http from 'node:http';
import https from 'node:https';

/**
 * Genuine BeEF REST API Client
 * Interacts with the real local BeEF REST API to manage and clean hooked browser sessions.
 * 
 * BeEF REST API endpoints utilized:
 * - POST /api/admin/login        -> Authenticate with BeEF server
 * - GET  /api/hooks?token=...    -> Query active online & offline hooked browsers
 * - GET  /api/hooks/:id/delete   -> Delete/terminate hooked browser session from BeEF DB
 */

export class BeefClient {
  constructor(options = {}) {
    this.apiUrl = options.apiUrl || process.env.BEEF_API_URL || 'http://127.0.0.1:3001';
    this.username = options.username || process.env.BEEF_USER || 'beef';
    this.password = options.password || process.env.BEEF_PASSWORD || 'beef';
    this.token = options.token || process.env.BEEF_TOKEN || null;
    this.timeout = options.timeout || 3000;
  }

  /**
   * Internal HTTP/HTTPS request helper with JSON parsing and timeout handling.
   */
  _request(endpoint, method = 'GET', body = null) {
    return new Promise((resolve, reject) => {
      try {
        const parsedUrl = new URL(endpoint, this.apiUrl);
        const isHttps = parsedUrl.protocol === 'https:';
        const client = isHttps ? https : http;

        const options = {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (isHttps ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          method: method,
          headers: {
            'Accept': 'application/json'
          },
          timeout: this.timeout
        };

        if (body) {
          const bodyStr = typeof body === 'object' ? JSON.stringify(body) : String(body);
          options.headers['Content-Type'] = 'application/json';
          options.headers['Content-Length'] = Buffer.byteLength(bodyStr);
        }

        const req = client.request(options, (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            let parsedBody = data;
            try {
              if (data && data.trim()) {
                parsedBody = JSON.parse(data);
              }
            } catch (e) {
              // Retain raw string if not JSON
            }
            resolve({
              statusCode: res.statusCode,
              headers: res.headers,
              body: parsedBody
            });
          });
        });

        req.on('timeout', () => {
          req.destroy();
          reject(new Error(`BeEF API request timed out after ${this.timeout}ms`));
        });

        req.on('error', (err) => {
          reject(err);
        });

        if (body) {
          const bodyStr = typeof body === 'object' ? JSON.stringify(body) : String(body);
          req.write(bodyStr);
        }

        req.end();
      } catch (err) {
        reject(err);
      }
    });
  }

  /**
   * Authenticates with the BeEF server to obtain a REST API token.
   */
  async authenticate() {
    if (this.token) return this.token;

    try {
      const res = await this._request('/api/admin/login', 'POST', {
        username: this.username,
        password: this.password
      });

      if (res.statusCode === 200 && res.body && res.body.token) {
        this.token = res.body.token;
        return this.token;
      }
      return null;
    } catch (err) {
      return null;
    }
  }

  /**
   * Retrieves all online and offline hooked browsers currently tracked by BeEF.
   */
  async getHookedBrowsers() {
    const token = await this.authenticate();
    if (!token) {
      return { available: false, online: [], offline: [] };
    }

    try {
      const res = await this._request(`/api/hooks?token=${encodeURIComponent(token)}`, 'GET');
      if (res.statusCode !== 200 || !res.body) {
        return { available: false, online: [], offline: [] };
      }

      const raw = res.body['hooked-browsers'] || res.body.hooks || res.body;
      const onlineRaw = (raw && raw.online) || {};
      const offlineRaw = (raw && raw.offline) || {};

      const normalizeList = (input) => {
        if (Array.isArray(input)) return input;
        if (typeof input === 'object' && input !== null) {
          return Object.values(input);
        }
        return [];
      };

      return {
        available: true,
        online: normalizeList(onlineRaw),
        offline: normalizeList(offlineRaw)
      };
    } catch (err) {
      return { available: false, online: [], offline: [] };
    }
  }

  /**
   * Determines if a hooked browser record is associated with the local XSS-Lab.
   * Compares domain, port, page_uri, and origin against lab parameters.
   */
  isLabSession(hookRecord, labHost = '127.0.0.1', labPort = 3000) {
    if (!hookRecord) return false;

    const pageUri = String(hookRecord.page_uri || hookRecord.url || '');
    const domain = String(hookRecord.domain || hookRecord.host || '');
    const port = String(hookRecord.port || '');
    const ip = String(hookRecord.ip || '');

    const labPortStr = String(labPort);
    const labHostMatch = labHost === '127.0.0.1' || labHost === 'localhost';

    // 1. Check page URI containing lab paths or host:port
    if (pageUri.includes(`:${labPortStr}`) || pageUri.includes('/labs/') || pageUri.includes('/reflected') || pageUri.includes('/stored') || pageUri.includes('/dom')) {
      return true;
    }

    // 2. Check domain & port match
    if (port === labPortStr && (domain === labHost || domain === '127.0.0.1' || domain === 'localhost')) {
      return true;
    }

    // 3. Check loopback origin with lab port
    if (labHostMatch && (ip === '127.0.0.1' || ip === '::1' || domain === 'localhost') && (port === labPortStr || !port)) {
      return true;
    }

    return false;
  }

  /**
   * Deletes a specific hooked browser session from BeEF's database.
   */
  async deleteSession(sessionIdOrId) {
    const token = await this.authenticate();
    if (!token || !sessionIdOrId) return false;

    try {
      // BeEF official REST API supports GET /api/hooks/:session/delete?token=...
      const res = await this._request(`/api/hooks/${encodeURIComponent(sessionIdOrId)}/delete?token=${encodeURIComponent(token)}`, 'GET');
      if (res.statusCode === 200) {
        return true;
      }

      // Alternative DELETE /api/hooks/:session?token=...
      const delRes = await this._request(`/api/hooks/${encodeURIComponent(sessionIdOrId)}?token=${encodeURIComponent(token)}`, 'DELETE');
      return delRes.statusCode === 200;
    } catch (err) {
      return false;
    }
  }

  /**
   * Cleans all hooked browser sessions originating from the local XSS-Lab.
   * Protects unrelated external sessions by verifying session ownership.
   */
  async cleanLabSessions({ labHost = '127.0.0.1', labPort = 3000 } = {}) {
    const token = await this.authenticate();
    if (!token) {
      return {
        success: false,
        status: 'unreachable_or_auth_failed',
        cleanedCount: 0,
        cleanedSessions: [],
        preservedCount: 0
      };
    }

    const { available, online, offline } = await this.getHookedBrowsers();
    if (!available) {
      return {
        success: false,
        status: 'query_failed',
        cleanedCount: 0,
        cleanedSessions: [],
        preservedCount: 0
      };
    }

    const allHooks = [...online, ...offline];
    let cleanedCount = 0;
    let preservedCount = 0;
    const cleanedSessions = [];

    for (const hook of allHooks) {
      const sessionId = hook.session || hook.id;
      if (this.isLabSession(hook, labHost, labPort)) {
        const deleted = await this.deleteSession(sessionId);
        if (deleted) {
          cleanedCount++;
          cleanedSessions.push(sessionId);
        }
      } else {
        preservedCount++;
      }
    }

    return {
      success: true,
      status: cleanedCount > 0 ? 'cleaned' : 'no_lab_sessions_found',
      cleanedCount,
      cleanedSessions,
      preservedCount
    };
  }
}

export const beefClient = new BeefClient();
