import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../../data');
const DATA_FILE = path.join(DATA_DIR, 'messages.json');

const DEFAULT_MESSAGES = [
  {
    id: 'msg-1',
    author: 'Alice',
    role: 'Security Analyst',
    website: 'https://example.local/alice',
    content: 'Welcome to the Stored XSS v2 testing laboratory! Try exploring multiple stored fields.',
    createdAt: '2026-08-31T09:00:00.000Z'
  },
  {
    id: 'msg-2',
    author: 'Bob',
    role: 'Software Engineer',
    website: 'https://example.local/bob',
    content: 'This is a normal user comment stored in local JSON storage.',
    createdAt: '2026-08-31T09:15:00.000Z'
  }
];

function ensureStorageFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(DEFAULT_MESSAGES, null, 2), 'utf8');
  }
}

export function getMessages() {
  ensureStorageFile();
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      if (raw.trim()) {
        return JSON.parse(raw);
      }
    } catch (err) {
      if (attempt === 2) {
        console.error('Error reading messages file:', err);
        return DEFAULT_MESSAGES;
      }
    }
  }
  return DEFAULT_MESSAGES;
}

function saveMessages(messages) {
  ensureStorageFile();
  const tmpFile = `${DATA_FILE}.tmp.${Date.now()}.${Math.random()}`;
  try {
    fs.writeFileSync(tmpFile, JSON.stringify(messages, null, 2), 'utf8');
    fs.renameSync(tmpFile, DATA_FILE);
  } catch (err) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(messages, null, 2), 'utf8');
    try { if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile); } catch(e) {}
  }
}

export function addMessage(authorOrObj, contentArg, roleArg, websiteArg) {
  ensureStorageFile();
  const messages = getMessages();
  
  let author = 'Anonymous';
  let content = '';
  let role = 'Community Member';
  let website = '';

  if (typeof authorOrObj === 'object' && authorOrObj !== null) {
    author = authorOrObj.author || 'Anonymous';
    content = authorOrObj.content || '';
    role = authorOrObj.role || 'Community Member';
    website = authorOrObj.website || '';
  } else {
    author = authorOrObj || 'Anonymous';
    content = contentArg || '';
    role = roleArg || 'Community Member';
    website = websiteArg || '';
  }

  const newMessage = {
    id: `msg-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    author: String(author),
    role: String(role),
    website: String(website),
    content: String(content),
    createdAt: new Date().toISOString()
  };

  messages.push(newMessage);
  saveMessages(messages);
  return newMessage;
}

export function resetMessages() {
  ensureStorageFile();
  saveMessages(DEFAULT_MESSAGES);
  return DEFAULT_MESSAGES;
}
