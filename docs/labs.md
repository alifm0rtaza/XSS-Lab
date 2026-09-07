# XSS-Lab Laboratory Guide

This document provides a comprehensive reference for the laboratories included in **XSS-Lab**.

---

## 1. Reflected XSS (`/labs/reflected`)

In Reflected XSS, untrusted user data sent in an HTTP request is immediately echoed by the server into the HTTP response body without contextual escaping.

### 3-Tier Structure
- **Tier 1 — Main Lab (`/labs/reflected/main`):** Recommended entry point. Features 5 genuine Express query parameters (`?q=`, `?search=`, `?name=`, `?message=`, `?id=`) across authentic routes (`/reflected/search`, `/reflected/results`, `/reflected/profile`, `/reflected/message`, `/reflected/item`).
- **Tier 2 — Core Contexts (`/labs/reflected/contexts`):**
  - *HTML Body Context:* Input placed directly between HTML tags.
  - *HTML Attribute Context:* Input placed inside tag attributes (`<input value="...">`).
  - *JavaScript String Context:* Input placed inside `<script>` string literals.
  - *URL / Link Context:* Input placed inside `<a href="...">` destinations.
- **Tier 3 — Advanced Challenges (`/labs/reflected/advanced`):** Explores blacklist filter evasion, attribute event handlers (`onload`, `onerror`), and script closure breakouts.

### Secure Counterparts
Every reflected scenario has a `/secure` route using context-appropriate encoding:
- `escapeHtml(str)` for HTML body
- `escapeHtmlAttr(str)` for HTML attributes
- `escapeJsString(str)` for JavaScript literals
- `sanitizeUrl(url)` with protocol whitelisting for URLs

---

## 2. Stored XSS (`/labs/stored`)

In Stored (Persistent) XSS, untrusted data submitted by an author is permanently saved to server storage (`data/messages.json`) and rendered unescaped to subsequent visitors.

### Features
- **Multi-Field Datastore:** Exercises Author Handle, Role/Title, Website URL, and Comment Content.
- **Authentic Two-Session Model:** Demonstrates how stored payloads execute in victim browsers independently of the author session.
- **`javascript:` Protocol Injection:** Demonstrates pseudo-protocol execution in user website links vs. protocol whitelisting in secure mode.

### Secure Counterparts
- Applies entity encoding to author and message body.
- Enforces strict URL protocol validation allowing only `http:`, `https:`, or relative paths (`#`, `/`).

---

## 3. DOM-Based XSS (`/labs/dom`)

In DOM-Based XSS, client-side JavaScript reads data from an attacker-controllable browser **Source** and passes it directly to an unsafe DOM **Sink** within the client runtime.

### Scenarios
1. **Scenario 1 (`innerHTML` Sink):** Reading `location.search` or `location.hash` and writing to `element.innerHTML`.
2. **Scenario 2 (`document.write` Sink):** Streaming unescaped input dynamically into document frames.
3. **Scenario 3 (Dynamic `href` Sink):** Assigning user input directly to `element.href`.

### Secure Counterparts
- Uses safe DOM properties (`element.textContent`, `document.createTextNode()`).
- Validates URL protocols before modifying navigation properties.

---

## 4. XSS Workbench (`/workbench`)

The **Testing Workbench** provides an interactive matrix comparing routes, HTTP methods, parameters, output contexts, and raw HTTP responses versus browser-rendered DOM trees.
