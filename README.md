**English** | **简体中文**: [README.zh.md](README.zh.md)

# pc-work-mcp · Windows Local Workbench MCP Server (for Gemini Web)

A pure, self-bootstrapping Windows local workbench MCP server built specifically for **Gemini Web (`gemini.google.com`)** remote MCP connectors, paired with an optional **Tampermonkey browser bridge** to overcome web-client sandbox and context limitations:

- **Zero Mandatory Third-Party Dependencies**: The server core runs purely on the Python standard library—extract and run.
- **Native Read-Only Search & Post-Edit Verification**: Built-in stdlib `find_files` and `grep_search` (no `exec` permission required, supporting `workspace.ignored_dirs` to skip history/cache folders). `write_file` and `edit_file` support atomic multi-hunk `edits`, mismatch line-number hints, automatic syntax checks (`.py` / `.json` / `.toml` / `.ps1` / optional `.js`), and structured lint/test feedback via `.gemini/checks.json`.
- **Lightweight Task Plans & Controlled Self-Wake (`task_plan`)**: Persists conversation task steps and auto-continue limits; works with the Tampermonkey bridge to auto-send a compact follow-up prompt after turn settle + cooldown + random jitter. The continuation prompt embeds current and next steps directly to avoid redundant fetches, and budget is deducted only after successful send.
- **First-Run Workspace Bootstrapping**: Prompts with a native Windows folder picker on first launch (canceling aborts cleanly without littering the Desktop; automatically falls back to the outer parent directory if already placed inside `<workspace>\Gemini-Windows-Mcp\`, or pass `--use-desktop-workspace` to create one on Desktop). All source files, configs, docs, and tests live inside `<workspace>\Gemini-Windows-Mcp\` to keep your workspace root clean.
- **Mandatory Local Auth Before Connection**: A local `auth.token` must be issued before the server will start or respond to OAuth / Google connector requests.
- **Transparent Media Boundaries & Canary Probe**: Clearly states current gateway/sandbox limitations in MCP `instructions` and tool descriptions, attaching a 1×1 canary pixel to detect if upstream image-read restrictions are relaxed.
- **On-Demand Dynamic Workspace Rules Injection (`workspace_rules`)**: Avoids brittle request-interception hacks. Automatically scans `AGENTS.md`, `GEMINI.md`, `.gemini/AGENTS.md`, `.gemini/GEMINI.md`, and `.gemini/rules/*.md` with SHA-256 tracking—injecting `<workspace_rules>` at the tail of tool outputs only on the **first tool call** of a session, when **rule files change or are deleted**, or when hitting re-anchor thresholds (default: every **20 tool calls** or **96,000 chars** of tool output) to counter web context compression and attention decay.
- **Zero Legacy Protocol Coupling**: Completely free of CDP injection, cookie scraping, or local reverse-proxy image hacks.

---

## 1. Prerequisites & Environment

As a local Windows workbench, user environments vary. Requirements are split into **required baseline** and **optional on-demand extensions**:

### Required (Minimum Baseline)
1. **Windows 10 / 11**
2. **Python 3.10+** (`server.py` uses only the Python standard library—**no `pip install` needed** to start)
3. **PowerShell** (built-in `powershell.exe` or PowerShell 7 `pwsh.exe`) as the baseline fallback shell.

### Optional / On-Demand (Does Not Block Startup)
- **Git Bash** (for the `bash` tool): Requires Git for Windows; if only PowerShell is available, the model falls back to `powershell` or guides installation.
- **Pillow (`pip install Pillow`)**: Used by `read_image` / `push_file` for resizing, EXIF rotation, and JPEG re-encoding; falls back to raw image bytes if absent.
- **Windows OCR Language Packs**: `read_image` optionally invokes WinRT `Windows.Media.Ocr`; if missing on stripped systems, OCR is skipped without breaking image reads.
- **Other CLI Tools & Python Packages** (e.g., `node`, `ffmpeg`, `pandas`, `openpyxl`, `python-docx`): **Never assumed pre-installed**. Instructions tell the model to inspect `workspace_status` (`engines`) first and ask/install as needed.
- **HTTPS Reverse Proxy / Tunnel** (e.g., `cloudflared`, `caddy`, `nginx`, `frp`): Needed only when exposing the local port (default `15672`) to cloud MCP clients like Google Gemini Web; set `oauth.public_base_url` in `config.json`.

---

## 2. Quick Start (Before Connecting Google / Gemini)

### Step 1: Initialize Workspace & Issue Local Auth Token

`config.json` ships without `auth.token` or a workspace path. You can **double-click `server.py` (or run `python server.py`)** to launch the interactive wizard, or run via CLI:

```powershell
python server.py --issue-token --public-url "https://your-public-domain:port"
```

(Omit `--public-url` for local-only testing. When sitting behind a reverse proxy such as `lucky`, `nginx`, or `caddy`, set `oauth.public_base_url` or pass `--public-url` so rewritten `Host` headers do not break Google OAuth registration.)

The wizard performs two steps in order:
1. **Select & Initialize Workspace**: Opens a native Windows folder picker (works even when launched via `.vbs` / console-less mode; or pass `--workspace "D:\MyWorkspace"` / `--no-gui` for CLI input).
   - Clicking **Cancel** aborts initialization cleanly without creating folders on Desktop.
   - If the repo is already inside `<workspace>\Gemini-Windows-Mcp\`, it defaults to the outer clean workspace.
   - Pass `--use-desktop-workspace` to explicitly create `pc-work-mcp-workspace` on Desktop.
   - All MCP source files, configs, docs, and tests are kept inside `<workspace>\Gemini-Windows-Mcp\`.
2. **Issue Local Auth Token**: Generates a high-entropy token (`pcmcp_...`), writes it to both the source and `<workspace>\Gemini-Windows-Mcp\config.json`, and prints it once in the terminal for copying. In interactive wizard mode, press Enter after saving to continue starting the server immediately.

Useful token commands:
- Check masked token status: `python server.py --token-status`
- Rotate token & revoke old OAuth sessions: `python server.py --rotate-token`

> Launching non-interactively / with `--config` before issuing a local token exits with code `2`, and OAuth endpoints (`/register`, `/authorize`, `/token`) return `403 local_token_not_issued`.

### Step 2: Allow Windows Inbound Firewall (If Reverse Proxy Is on Another Host)

If your reverse proxy or tunnel (e.g., `lucky`, `nginx`, `caddy`, or `frp` on a router, NAS, or another host) connects to Windows port `15672` over LAN, **run PowerShell as Administrator to add the inbound firewall rule first**:

```powershell
# Run as Administrator in the project/workspace directory (allows LocalSubnet -> TCP 15672 by default)
powershell -ExecutionPolicy Bypass -File ".\admin\add-firewall.ps1"

# Optional custom port or specific proxy IP:
# powershell -ExecutionPolicy Bypass -File ".\admin\add-firewall.ps1" -Port 15672 -RemoteAddress "<PROXY_IP>"
```

(Applies to `Private,Domain` profiles by default; ensure your Windows network profile is set to Private. Skip this step if your reverse proxy runs on the same Windows machine over `127.0.0.1`.)

### Step 3: Start Server & Connect

Start from the organized `Gemini-Windows-Mcp` subdirectory inside your workspace:

```powershell
python "<your-workspace-path>\Gemini-Windows-Mcp\server.py"
```

- **On-Demand Public Connectivity Check**: `oauth.startup_tcp_check` defaults to `false` so `server.py` starts cleanly even before configuring a public domain. Once your domain/proxy is ready, click **"🌐 Test Dual-Stack Public TCP Connectivity"** in the Tampermonkey panel (or run `python server.py --check-public-url`) before adding the connector in Gemini. Set `oauth.startup_tcp_check` to `true` in `config.json` to enforce checks on every startup.
- When adding the custom MCP server in Google / Gemini, use your local token as the Bearer Token or `/authorize` passphrase.

---

## 3. Runtime Prompt & Boundary Design for Models

Once connected, MCP `initialize.instructions` and tool descriptions (`workspace_status`, `read_image`, `push_file`) communicate four runtime rules to the model:

1. **Current Media Boundaries (Effective as of 2026-11-26)**:
   - Images generated in Gemini Web are locked inside its web sandbox and cannot be exported back through MCP tool responses.
   - Local images returned via MCP image blocks are stripped by the cloud gateway before reaching the model.
   - **Canary Probe**: `workspace_status` attaches a 1×1 probe pixel—if the model sees it, upstream image-read restrictions have been relaxed.
2. **Environment-Adaptive Delivery**:
   - Check `engines` from `workspace_status` before assuming `bash` or third-party Python libraries exist; fall back to PowerShell or install dependencies on demand.
3. **Never Edit Running MCP Entrypoints In-Place**:
   - Even though the source code is inside the workspace for customization, models are strictly instructed **not** to modify currently running server/tool definitions in-place (create a new versioned folder instead and let the user switch/restart).
4. **Dynamic `workspace_rules` Injection**:
   - Automatically discovers `AGENTS.md`, `GEMINI.md`, `.gemini/AGENTS.md`, `.gemini/GEMINI.md`, and `.gemini/rules/*.md` in the active workspace (including per-conversation bound directories), injecting on first tool call, file hash change, or every 20 calls / 96,000 output chars.

---

## 4. Tampermonkey Browser Bridge (`userscript/`)

To work around cloud gateway media stripping and web sandbox isolation, the distribution includes an async Tampermonkey bridge (`userscript/pc-work-mcp-gemini-bridge.user.js`):

1. **Installation**:
   - Enable **"Allow User Scripts"** in Chrome/Brave extension details for Tampermonkey.
   - With `pc-work-mcp` running, open:
     `http://127.0.0.1:15672/bridge/pc-work-mcp-gemini.user.js?token=<your-local-token>`
     for one-click installation (or import `userscript/pc-work-mcp-gemini-bridge.user.js` manually and set the server URL + token in the floating panel).
2. **Key Capabilities**:
   - **Conversation ID Tracking & First-Turn Capture**: Tracks `/app/<id>` (including pre-ID first turns) via `POST /bridge/heartbeat`.
   - **Per-Conversation Permission Control (Recommended)**:
     - Without the userscript, the server falls back to workspace default permissions.
     - With the userscript active, each Gemini conversation URL (`/app/<conversation_id>`) gets independent permissions (`Ask / Read-Only / Media-Bridge Only / Workspace Read-Write / Full Workbench / Deny` presets plus 5 granular checkboxes).
     - Managed strictly locally via `auth.token` + Tampermonkey (`GET/POST /bridge/permissions`)—remote OAuth tokens cannot access control-plane endpoints, and workspace MCP tools cannot tamper with permission configs.
   - **Per-Conversation Workspace Switching**:
     - Bind any local folder to a specific Gemini conversation URL via the native Windows folder picker or saved path list. Relative paths, green-zone write boundaries, default `cwd`, `.mcp_snapshots/`, `.tmp_outputs/`, and `AGENTS.md` rule discovery all switch cleanly to that folder.
   - **Global Whitelist Directories (Cross-Conversation Access)**:
     - Pin shared folders (e.g., personal notes, knowledge bases, diary folders) to `workspace.extra_allowed_dirs` with per-folder `readwrite` / `readonly` and optional `allow_exec` toggles, hot-reloaded without restarting the server. System directories and MCP control-plane files remain strictly protected.
   - **Auto-Upload & Send Local Media (`bridge_upload_media`)**: Agent calls the tool and stops its turn; the userscript locates the conversation, injects local images/videos/audio/docs, waits for upload completion, and clicks Send automatically.
   - **Save Web-Generated Media to Disk (`bridge_save_generated_media`)**: Agent specifies a target local path/folder and stops its turn; the userscript extracts generated images/videos/music from the authenticated browser session (with high-res Canvas fallback if `blob:` URLs are revoked) and writes them via MCP (outside-workspace writes trigger local approval popups).
   - **Controlled Self-Wake (`task_plan` `schedule_continue`)**: Queues a compact continuation prompt when approaching single-turn step limits; the userscript waits for turn idle + cooldown (≥5s) + jitter, shows a cancellable countdown bar, and auto-sends up to the configured `max_auto_turns` cap (default 5).

---

## 5. Tool Inventory (20 Core Tools)

| Category | Tools | Description |
|---|---|---|
| Command Execution | `powershell` / `python` / `bash` | Sync execution (default 60s / max 180s); outputs >16KB spill to `.tmp_outputs/` |
| Async Jobs | `start_job` / `get_job_status` / `kill_job` | Detached process-group background jobs and full tree termination |
| Status & Boundaries | `workspace_status` | Engine probe, active workspace, jobs, task plan, boundary notice, and 1×1 canary pixel |
| Read-Only Search | `list_dir` / `find_files` / `grep_search` | Pure stdlib listing, glob search, and text/regex search (`read` permission, respects `workspace.ignored_dirs`) |
| File R/W & Checks | `read_file` / `write_file` / `edit_file` | Three-zone boundary + pre-write `.bak` snapshots + atomic multi-hunk `edits` + instant syntax checks & `.gemini/checks.json` |
| Image & Delivery | `read_image` / `push_file` | Local image read (with optional WinRT OCR) and signed `/files/` temporary download links |
| Task Planning | `task_plan` | Lightweight persistent plan state (`logs/task_plans.json`) and controlled self-wake continuation |
| Browser Bridge | `bridge_status` / `bridge_upload_media` / `bridge_save_generated_media` / `bridge_get_task` / `bridge_suggest_ignore_dirs` | Conversation sync, auto media upload/send, generated media download, and `ignored_dirs` suggestion popups |

---

## 6. Design Scope & Known Limitations (Intentionally Lightweight)

This project is intentionally scoped as a **lightweight local workbench MCP for Gemini Web** rather than a heavy autonomous harness (avoiding aggressive background polling, multi-worktree orchestration, or deep frontend RPC hijacking that increase maintenance overhead and upstream rate-limit risk):

1. **Lightweight Security Guard (`security.py`)**: Uses rule/regex-based path inspection rather than full AST subcommand parsing, outbound network firewalls, or container sandboxing.
2. **Snapshots Without Multi-File Transactions**: `.mcp_snapshots/` retains up to 20 `.bak` backups per file, but there is no multi-file transactional rollback tool or optimistic mtime/SHA file locking across concurrent tabs.
3. **In-Memory Jobs & Bridge Queues**: Permissions, rules, workspace bindings, and `task_plan` persist on disk, while running `start_job` processes and pending bridge media tasks reside in memory and do not survive server restarts.
4. **Gemini Web Host Constraints**: Gemini Web does not render MCP `notifications/progress`, clicking "Stop generating" in the browser does not interrupt already-spawned sync `powershell`/`python`/`bash` processes (use `start_job` for long tasks), concurrent generating tabs fall back to the default workspace for `ALWAYS_ALLOWED_TOOLS`, and `workspace_rules` only re-anchors on turns that invoke tools.

---

## 7. Running Self-Tests

```powershell
python -m unittest discover -s tests -v
```
