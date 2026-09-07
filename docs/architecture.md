# XSS-Lab Technical Architecture

This document outlines the internal architecture, state management, and execution detection mechanisms in **XSS-Lab**.

---

## 1. Core Design Principles

- **Zero Heavy Dependencies:** Built on native Node.js and lightweight Express.
- **Genuine HTTP Flows:** Uses authentic Express route handlers, real query parameters, and natural browser parsing.
- **Safe by Default:** The application binds strictly to the loopback interface (`127.0.0.1:3000`) by default.

---

## 2. Storage & State Management

- **Persistent JSON Datastore:** Managed by [`src/storage/messageStore.js`](file:///c:/Users/User/Documents/Projects/XSS-Lab/src/storage/messageStore.js). Automatically initializes `data/messages.json` with benign seed comments if the file does not exist.
- **Two-Tier Reset Architecture:**
  - *Module Reset (`POST /api/stored/reset`):* Wipes and re-seeds `data/messages.json` without modifying other states.
  - *Full Lab Restore (`POST /api/lab/restore`):* Purges temporary files in `data/`, resets stored messages, clears client-side browser storage (`localStorage`, `sessionStorage`, cookies), and terminates lab-created sessions from local BeEF instances.

---

## 3. Client-Side Execution Detection & Modal

- Handled in [`src/server/utils.js`](file:///c:/Users/User/Documents/Projects/XSS-Lab/src/server/utils.js).
- Intercepts native `window.alert()`, `window.confirm()`, and `window.prompt()` calls to display a clean, centered educational modal.
- Shows the active XSS Type, Challenge Context, DOM Sink, Execution Source, and supplied payload string without locking browser tabs or blocking automated test runners.

---

## 4. Reality Status Matrix

The application separates execution reality into three independent states:
1. **Reflection:** Server echoes user input bytes in the HTTP response.
2. **HTML Injection:** Injected characters parse as active HTML elements/attributes.
3. **JavaScript Execution:** Injected code executes within the browser's JavaScript runtime engine.
