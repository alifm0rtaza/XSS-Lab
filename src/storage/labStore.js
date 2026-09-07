import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resetMessages, getMessages } from './messageStore.js';
import { BeefClient } from './beefClient.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../../data');

/**
 * Lab Datastore and Factory Reset Manager
 * Orchestrates complete factory state restoration across local JSON storage,
 * runtime session artifacts, and genuine BeEF hook terminations.
 */

// Active in-memory session registry / heartbeat tracking
let activeLabSessionIds = new Set();

export function registerLabSession(sessionId) {
  if (sessionId) activeLabSessionIds.add(String(sessionId));
}

export function invalidateAllLabSessions() {
  const count = activeLabSessionIds.size;
  activeLabSessionIds.clear();
  return count;
}

export function isLabSessionValid(sessionId) {
  return activeLabSessionIds.has(String(sessionId));
}

/**
 * Purges runtime data files (sessions, events, telemetry, temporary files)
 * while preserving directory structure and re-seeding default messages.
 */
export function purgeRuntimeDataFiles() {
  const purged = [];
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    return purged;
  }

  const files = fs.readdirSync(DATA_DIR);
  for (const file of files) {
    // Keep messages.json for explicit reseed; purge all other runtime files
    if (file === 'messages.json') continue;

    const fullPath = path.join(DATA_DIR, file);
    try {
      const stat = fs.statSync(fullPath);
      if (stat.isFile()) {
        fs.unlinkSync(fullPath);
        purged.push(file);
      }
    } catch (e) {
      // Ignore cleanup error for individual file
    }
  }

  return purged;
}

/**
 * Full Lab Restore: Performs complete factory reset across all local components.
 */
export async function restoreFullLab({
  labHost = process.env.HOST || '127.0.0.1',
  labPort = parseInt(process.env.PORT || '3000', 10),
  beefClientInstance = null
} = {}) {
  const timestamp = new Date().toISOString();

  // 1. Reset Stored XSS messages to default initial seed
  const defaultMessages = resetMessages();

  // 2. Purge runtime data files (sessions.json, events.json, telemetry.json, tmp files)
  const purgedFiles = purgeRuntimeDataFiles();

  // 3. Invalidate in-memory session/heartbeat tracking
  const invalidatedSessionsCount = invalidateAllLabSessions();

  // 4. Genuine BeEF REST API session cleanup
  const beef = beefClientInstance || new BeefClient();
  let beefResult = {
    attempted: true,
    success: false,
    status: 'skipped',
    cleanedCount: 0,
    cleanedSessions: [],
    preservedCount: 0
  };

  try {
    beefResult = await beef.cleanLabSessions({ labHost, labPort });
  } catch (err) {
    beefResult = {
      attempted: true,
      success: false,
      status: 'error',
      error: err.message,
      cleanedCount: 0,
      cleanedSessions: [],
      preservedCount: 0
    };
  }

  // 5. Determine high-level status message
  let displayMessage = 'Lab restored to factory state.';
  if (!beefResult.success && beefResult.status === 'unreachable_or_auth_failed') {
    displayMessage = 'XSS-Lab restored, but the local BeEF session could not be cleaned (BeEF server unreachable).';
  } else if (!beefResult.success && beefResult.status === 'query_failed') {
    displayMessage = 'XSS-Lab restored, but BeEF session query failed.';
  }

  return {
    success: true,
    message: displayMessage,
    timestamp,
    storage: {
      messagesCount: defaultMessages.length,
      purgedFiles,
      invalidatedSessionsCount
    },
    beef: beefResult
  };
}

/**
 * Retrieves current lab runtime status.
 */
export async function getLabStatus({
  labHost = process.env.HOST || '127.0.0.1',
  labPort = parseInt(process.env.PORT || '3000', 10),
  beefClientInstance = null
} = {}) {
  const messages = getMessages();
  const beef = beefClientInstance || new BeefClient();
  const beefStatus = await beef.getHookedBrowsers();

  return {
    online: true,
    messagesCount: messages.length,
    activeLabSessions: activeLabSessionIds.size,
    beefConnected: beefStatus.available,
    beefOnlineCount: beefStatus.online.length,
    beefOfflineCount: beefStatus.offline.length
  };
}
