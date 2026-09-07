# Troubleshooting Guide

Common setup questions and solutions for **XSS-Lab**.

---

## 1. Port 3000 Already in Use (`EADDRINUSE`)

If port `3000` is currently occupied by another service:

- **Linux / macOS:**
  ```bash
  PORT=3005 npm start
  ```
- **Windows PowerShell:**
  ```powershell
  $env:PORT="3005"; npm.cmd start
  ```
- **Windows Command Prompt:**
  ```cmd
  set PORT=3005 && npm start
  ```

---

## 2. Windows PowerShell Execution Policy Error

If you see `npm.ps1 cannot be loaded because running scripts is disabled on this system`:

Run using `npm.cmd`:
```powershell
npm.cmd start
npm.cmd run dev
npm.cmd test
```

---

## 3. Storage Directory & File Creation

The `data/` directory uses a `.gitkeep` placeholder in version control. On initial application start or test run, `messages.json` is automatically created with default seed records. If the file is ever removed or corrupted, calling `POST /api/lab/restore` or restarting the server will recreate it automatically.

---

## 4. BeEF Server Unreachable During Restore

If BeEF is not running locally, calling **Restore Entire Lab** will output:
`"XSS-Lab restored, but the local BeEF session could not be cleaned (BeEF server unreachable)."`

This is normal and expected when running without an active BeEF instance; all local datastores and sessions are reset successfully.
