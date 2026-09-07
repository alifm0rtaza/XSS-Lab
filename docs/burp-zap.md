# Testing with Burp Suite & OWASP ZAP

**XSS-Lab** uses standard HTTP query parameters, form POST bodies, and raw responses, making it fully inspectable with local web proxies.

---

## 1. Proxy Configuration

1. **Proxy Listener:** Configure Burp Suite or OWASP ZAP to listen on `127.0.0.1:8080`.
2. **Browser Settings:** Direct your browser's proxy traffic to `127.0.0.1:8080`.
3. **Bypass List Check:** Ensure your browser's proxy configuration does not bypass `localhost` or `127.0.0.1`.

---

## 2. Testing Scenarios

- **Parameter Tampering:** Intercept `GET /reflected/search?q=...` or `GET /reflected/profile?name=...` to test URL encoding variations, delimiter breakouts, and character filtering.
- **Multi-Field Inspection:** Intercept `POST /labs/stored` to test individual field boundaries (`author`, `role`, `website`, `content`).
- **Header Analysis:** Inspect response headers (`Content-Type: text/html; charset=utf-8`) and observe how the raw bytes returned by the server are rendered by the client browser.
