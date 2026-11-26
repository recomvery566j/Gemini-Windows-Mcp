# pc-work-mcp · Windows 本机工作台 MCP 服务（分发版）

一个纯粹、可自举的 Windows 本机工作台 MCP 服务：

- **零第三方强制依赖**：服务端本体仅使用 Python 标准库，解压即可运行。
- **原生只读检索与写后轻量校验**：内置纯标准库 `find_files` / `grep_search`（无需消耗 `exec` 权限）；`write_file` / `edit_file` 自动执行瞬时语法检查与可选工程 `lint/test` 命令并结构化回喂，充分利用网页端受限的单轮执行步数。
- **轻量任务计划与受控自唤醒（`task_plan`）**：持久化当前会话的任务步骤与自动续跑次数上限，配合油猴桥接在停稳冷却+随机抖动后自动唤醒下一回合继续完善目标；提示词强制极简交接（≤120 字）防上下文膨胀，油猴端随时可一键暂停。
- **首次工作区自举**：首次运行弹出工作区选择框（取消即中止初始化，不会乱建桌面目录；若已置于 `<工作区>\Gemini-Windows-Mcp\` 子目录下则自动回退到外层干净工作区，也可用 `--use-desktop-workspace` 显式建在桌面），并把全套源码、配置、文档与测试一次性放到工作区的 `Gemini-Windows-Mcp\` 子目录下，工作区根目录保持洁净。
- **连接前强制本地鉴权**：必须先在本地派发 `auth.token` 后才能启动服务或响应 OAuth / Google 连接。
- **透明的媒体边界与动态探针**：在 MCP `instructions` 与工具提示词中明确当前网关/沙箱边界缺陷，并附带 1×1 像素探测图以感知上游限制是否松动。
- **按需动态工作区提示词注入（`workspace_rules`）**：无需依赖容易因 Google 前端变更而失效的发包劫持，自动扫描工作区 `AGENTS.md`、`GEMINI.md`、`.gemini/rules/*.md` 并计算 SHA-256——仅在会话**首次调用任意工具**、**规则文档发生修改/增删**、或长上下文下达到重锚阈值（默认每 **20 步**工具调用或累计 **48,000 字符**工具输出，先到先触发）时，将最新 `<workspace_rules>` 块附带在工具返回尾部以对抗网页随机压缩与长程注意力衰减。
- **无历史外部协议耦合**：已彻底移除 CDP 注入、Cookie 抓包及本地反代生图/读图通道。

---

## 1. 默认需要什么工具与环境

作为本机工作台，不同用户的系统环境差异较大，请区分**必须基线**与**按需扩展**：

### 必须（最小运行基线）
1. **Windows 10 / 11**
2. **Python 3.10+**（`server.py` 仅依赖 Python 标准库，**无需预先安装任何 `pip` 第三方包**即可启动）
3. **PowerShell**（Windows 自带 `powershell.exe`，或 PowerShell 7 `pwsh.exe`）——作为最基础的兜底命令行执行环境。

### 可选 / 按需安装（未预装不影响服务启动）
- **Git Bash**（用于 `bash` 工具）：需要安装 Git for Windows；若本机仅 PowerShell 可用，模型应改用 `powershell` 或引导/协助安装 Bash。
- **Pillow (`pip install Pillow`)**：用于 `read_image` / `push_file` 的缩放、EXIF 旋转与 JPEG 重编码；未安装时自动退化为直接发送原图字节。
- **Windows OCR 语言包**：`read_image` 的可选文字识别调用 WinRT `Windows.Media.Ocr`；若系统精简或缺少对应语言包，仅跳过 OCR，不影响图像读取。
- **其他命令行工具与 Python 库**（如 `node`、`ffmpeg`、`pandas`、`openpyxl`、`python-docx` 等）：**不假定预装**。提示词已明确告知模型：应先通过 `workspace_status` 查看实际可用引擎，缺工具/缺库时按需由用户安装或由模型自行安装，以完成任务交付。
- **HTTPS 反代 / 内网穿透**（如 `cloudflared`、`caddy`、`nginx`、`frp` 等）：仅当需要把本地监听端口（默认 `15672`）暴露给云端服务（如 Google / Gemini MCP 连接器）时配置，并在 `config.json` 中填写 `oauth.public_base_url`。

---

## 2. 快速开始（连接 Google 服务前必做）

### 第一步：首次初始化工作区 + 本地派发鉴权 Token

`config.json` 默认不包含 `auth.token` 与工作区路径。你可以直接**双击 `server.py`（或执行 `python server.py`）进入向导**，也可手动执行命令行：

```powershell
python server.py --issue-token --public-url "https://你的公网域名:端口"
```

（若仅本机调试可省略 `--public-url`；若经 `lucky` 等反向代理连接 Google MCP，建议务必填写 `oauth.public_base_url` 或传 `--public-url`，防止代理改写 `Host` 头导致 Google OAuth 自动注册拿到内网 IP 而失败。）

向导或上述命令会按顺序完成两件事：
1. **选择并初始化工作区**：弹出 Windows 文件夹选择框（即使通过 `.vbs` / 无控制台窗口启动也会正常弹出；也可用 `--workspace "D:\MyWorkspace"` 指定，或 `--no-gui` 走命令行输入）。
   - 如果在弹窗中点击**「取消」**：会直接中止初始化并退出，不会私自在桌面新建目录或复制文件；
   - 如果你已把程序目录整理进 `<工作区>\Gemini-Windows-Mcp\`，未另选目录时会自动回退到外层干净工作区；
   - 如确需建在当前桌面 `pc-work-mcp-workspace`，可显式加参数 `--use-desktop-workspace`。
   - 为保持工作区根目录洁净，全部 MCP 源码、配置、文档与测试统一保存在工作区内的 `Gemini-Windows-Mcp\` 子目录中。
2. **派发本地鉴权 Token**：生成高强度随机 token（`pcmcp_...`），同步写入源目录与 `<工作区>\Gemini-Windows-Mcp\config.json`，并在终端**明文打印 Token 与复制保存提示**；若是双击/交互运行 `server.py` 触发的向导，回车确认已保存后即可直接继续启动服务（不会闪退）。

常用辅助命令：
- 查看当前 token 状态（脱敏）：`python server.py --token-status`
- 轮换 token 并作废旧 OAuth 会话：`python server.py --rotate-token`

> 若非交互/指定 `--config` 启动且未先派发本地 token，服务会严格拒绝启动（退出码 `2`），且 `/register`、`/authorize`、`/token` 等 OAuth 端点会返回 `403 local_token_not_issued`。

### 第二步：放行 Windows 入站防火墙（跨主机反代/局域网访问必做）

如果你的反向代理或内网穿透（如路由器/NAS/另一台主机上的 `lucky`、`nginx`、`caddy`、`frp`）需要从本机以外访问 Windows 的监听端口（默认 `15672`），**连接前必须先以管理员身份运行 PowerShell 放行入站规则**，否则 Windows 防火墙会直接丢弃入站流量：

```powershell
# 以管理员身份打开 PowerShell，在项目或工作区目录执行（默认放行同网段 LocalSubnet 到 TCP 15672）
powershell -ExecutionPolicy Bypass -File ".\admin\add-firewall.ps1"

# 如自定义端口或反代来自特定 IP / 跨网段 / 虚拟组网，可按需传参：
# powershell -ExecutionPolicy Bypass -File ".\admin\add-firewall.ps1" -Port 15672 -RemoteAddress "<反代主机IP>"
```

（默认规则作用于 `Private,Domain` 网络配置，请确认 Windows 当前网络为「专用网络」；若反代进程与 `pc-work-mcp` 运行在同一台 Windows 上且仅回环走 `127.0.0.1`，可跳过此步。）

### 第三步：启动服务并连接

建议直接从工作区内已整理好的 `Gemini-Windows-Mcp` 子目录启动：

```powershell
python "<你的工作区路径>\Gemini-Windows-Mcp\server.py"
```

- **公网连通性按需自检（不阻断默认启动）**：`oauth.startup_tcp_check` 默认为 `false`，确保在尚未配置公网域名或反代时双击/直接启动 `server.py` 也能正常运行；待你配置好域名和反代后，**在设置 Google / Gemini MCP 服务前**，强烈建议直接在**油猴面板点击「🌐 测试外网双栈 TCP 连通性」**（或运行 `python server.py --check-public-url`）确认外网 IPv6 / IPv4 确实能连入本机。若希望每次启动自动强检，可在 `config.json` 将 `oauth.startup_tcp_check` 设为 `true`。
- 连接 Google / Gemini 自定义 MCP 时，使用本地派发的 token 作为 Bearer Token 或 `/authorize` 授权页的访问口令。

---

## 3. 给模型的运行时提示词约束说明

连接成功后，MCP `initialize.instructions` 与 `workspace_status` / `read_image` / `push_file` 提示词会向模型明确三件事：

1. **当前媒体边界缺陷（截至 2026-11-26 生效）**：
   - Gemini 网页端生图内容被锁定在沙箱内，无法通过 MCP 回传落盘；
   - 用户电脑内的图片也无法通过 MCP 到达模型层面，会被网关层面丢弃；
   - 动态探测规则：**如果你发现调用时 MCP 会塞一个小像素点到眼前（如 `workspace_status` 附带的 1×1 像素探测图），就证明 Google 放开了读的权限；至于能不能写入，还是交由 Agent 判断。**
2. **环境自适应与交付原则**：
   - 不假定预装库或 Bash 必然存在，先以 `workspace_status` 返回的 `engines` 为准；如果只有 PowerShell 可用，引导用户或由模型自行安装所需工具/依赖以交付结果。
3. **严禁原地改坏运行中工具**：
   - 虽然工作区内包含全部源码与提示词方便定制，但**严禁直接修改正在运行且被当前会话调用的工具文件/接口**，以免工具链失效；如需调整提示词或扩展代码，必须先在工作区内新建独立目录（新版本文件夹）修改，再由用户切换重启。
4. **动态工作区提示词注入（`workspace_rules`）**：
   - 自动发现当前工作区（或按会话链接单独绑定的目录）中的 `AGENTS.md`、`GEMINI.md`、`.gemini/AGENTS.md`、`.gemini/GEMINI.md` 与 `.gemini/rules/*.md`。
   - 触发策略：在每个会话**首次调用任意工具**时注入；当规则文件**哈希发生变化或被删除**时立即在下次工具调用更新；在长对话中为对抗网页端随机上下文压缩与长程注意力衰减，每累计 **20 步工具调用**或 **48,000 字符工具输出**（先到先触发，均可在 `config.json` 中调整）自动重新锚定一次。
   - 若工作区内尚无任何规则文件，则静默跳过，不产生多余噪声；一旦创建规则文档，下一次工具调用即刻生效。

---

## 4. 油猴脚本联动（Tampermonkey Bridge）

为解决云端网关丢弃 MCP 图像块与网页沙箱生图无法回传落盘的问题，分发版内置了基于 Tampermonkey 的异步浏览器桥接（`userscript/pc-work-mcp-gemini-bridge.user.js`）：

1. **安装与浏览器设置**：
   - 在 Chrome / Brave 的扩展详情页开启 **「允许运行用户脚本」**；
   - 启动本地 `pc-work-mcp` 后，在浏览器直接打开：
     `http://127.0.0.1:15672/bridge/pc-work-mcp-gemini.user.js?token=<你的本地token>`
     即可一键安装（或手动导入 `userscript/pc-work-mcp-gemini-bridge.user.js` 后在浮标/油猴菜单填写地址与 Token）。
2. **核心联动能力**：
   - **会话 ID 透传与首轮异步捕获**：油猴自动监听当前 Gemini 会话 `/app/<id>`（以及首轮回复前无 ID、生成结束后才分配 ID 的场景）并实时上报 `POST /bridge/heartbeat`。
   - **按会话链接细化权限控制（强烈建议启用）**：
     - 未连接油猴插件时，服务端先以**工作区默认权限兜底**；
     - 一旦安装启用油猴本地桥脚本，即切换为**按每个 Gemini 会话链接（`/app/<conversation_id>`）独立授权**（支持预设档位 `按需询问 / 仅只读 / 仅媒体桥接 / 工作区读写 / 完全工作台 / 禁止` 以及 5 项细粒度权限勾选，含首轮临时 Tab 授权自动转绑、多窗口并发歧义降级）；
     - 权限策略仅由用户通过本机 `auth.token` + 油猴本地桥管理（`GET/POST /bridge/permissions`），远程 OAuth token 被拒绝访问控制面，工作区内 MCP 工具也无法篡改权限配置文件——**不由会话内 Agent 掌管，也不由 Google 掌管**。
   - **按会话选择与切换工作区目录（与默认工作区逻辑完全一致）**：
     - 可在油猴弹窗中点击「本机选文件夹并绑定」触发 Windows 原生目录选择器，或直接粘贴目录路径保存为常用工作区清单并绑定到当前 Gemini 会话链接（同样支持首轮 `/app` 提前绑定并在生成首条回复后自动转绑到 `/app/<id>`）；
     - 一旦某个会话绑定了切换目录，该会话内所有相对路径（`read_file`/`write_file`/`edit_file`/`list_dir`/`push_file`）、绿区写入边界、命令默认 `cwd`、`.mcp_snapshots/` 备份、`.tmp_outputs/` 大输出旁路、以及 `AGENTS.md` 规则探测都自动切换至该目录并保持与默认工作区完全一致的行为（同时写回原默认工作区或控制面文件仍受边界拦截）；点击「恢复默认工作区」即可随时切回。
   - **全局白名单目录（跨会话免重复授权，如本地日记本/知识库）**：
     - 若某个本地文件夹（例如个人日记本、笔记库）需要几乎所有新对话都能随时读写，可在油猴弹窗「全局白名单目录」中通过系统选目录或粘贴路径直接添加（持久化至 `config.json` 的 `workspace.extra_allowed_dirs` 并即时热生效，无需重启服务）。
     - 白名单内目录在**所有未设为「禁止 (deny)」的会话**中对文件/目录/检索/媒体工具直接免审批放行，不再每轮弹窗或要求切换整套会话档位；支持每条目录单独切换 **`自由读写 (readwrite)`** / **`仅只读 (readonly)`**，以及可选勾选 **`允许以该目录为 cwd 免批执行脚本`**（默认关闭以保持安全），同时系统保留目录（`System32` 等）与 MCP 控制面文件（`config.json`、`bridge_*.json` 等）依然受严格保护。
     - Agent 可通过 `workspace_status` 返回的 `global_whitelist` 字段直接知悉这些目录与权限模式。
   - **读图 / 读视频自动上传并发送（`bridge_upload_media`）**：Agent 调用后**必须立即停止当前回合输出**；油猴会定位或打开对应 `conversation_id` 会话、注入本地媒体、监听上传进度与 `push.clients6.google.com/upload` 彻底完成后自动点击发送。
   - **网页生图 / 视频 / 音乐下载落盘（`bridge_save_generated_media`）**：Agent 传入本机目标目录或路径并停止当前回合输出；油猴在生成完成后于浏览器登录态内提取原图/视频/音乐字节（含 `blob:` 回收时的 Canvas 高清回退）并回传 MCP 写入指定路径（工作区外变更受本地弹窗审批保护）。
   - **受控自唤醒续跑（`task_plan` `schedule_continue`）**：当网页端接近单轮步数上限而任务尚未收口时，模型可写入精简目标/步骤并通过 `schedule_continue` 入队续跑；油猴会在本回合完全停稳、经过最短冷却（≥5s）并叠加随机抖动后自动发送极简自唤醒提示词，同时右下角弹出可随时一键「暂停取消」的倒计时条，并受单计划自动轮数上限（默认 5 轮）熔断保护。

---

## 5. 工具清单（20 个核心工具）

| 类别 | 工具名 | 说明 |
|---|---|---|
| 命令执行 | `powershell` / `python` / `bash` | 同步执行（默认 60s / 上限 180s），输出超 16KB 自动旁路落盘到 `.tmp_outputs/` |
| 异步作业 | `start_job` / `get_job_status` / `kill_job` | 独立进程组长任务管理与整树终止 |
| 状态与边界 | `workspace_status` | 返回引擎探测、工作区、活跃作业、计划进度、边界声明与 1×1 像素探针 |
| 只读检索 | `list_dir` / `find_files` / `grep_search` | 纯标准库目录列举、通配符找文件与全文/正则检索（均归属 `read` 权限，无需 `exec`） |
| 文件读写与校验 | `read_file` / `write_file` / `edit_file` | 三区边界 + 写前 `.bak` 快照 + 写后瞬时语法检查（`.py`/`.json`/可选 `.js`）与可选 `.gemini/checks.json`（需 `exec`）结构化回喂 |
| 图像与投递 | `read_image` / `push_file` | 本地读图（含可选 WinRT OCR）与 `/files/` 签名临时下载链接 |
| 任务计划 | `task_plan` | 轻量持久化计划状态机（`logs/task_plans.json`）与受控自唤醒续跑（强制极简 `handoff`） |
| 油猴桥接 | `bridge_status` / `bridge_upload_media` / `bridge_save_generated_media` / `bridge_get_task` | 会话 ID 联动、自动上传发送、生成产物按目标目录下载落盘 |

> **写后自动 lint/test 配置提示**：无需配置即可对 `.py` / `.json` / `.js` 自动做毫秒级语法校验；若希望改完代码同时自动跑项目 lint 或单元测试，可在服务端 `config.json` 的 `post_edit_checks.on_edit_commands` 或在项目工作区新建 `.gemini/checks.json`（示例：`{"enabled": true, "on_edit": true, "timeout_sec": 15, "commands": [{"name": "test", "cmd": "python -m unittest", "extensions": [".py"]}]}`；注：工作区内 `.gemini/checks.json` 仅在当前会话具备 `exec` 权限时触发）。

---

## 6. 当前定位与已知不足（为何有意保持轻量化，非重型 Harness）

本项目有意定位为**面向 Gemini 网页端的轻量级本机工作台 MCP**——重型自动化 Harness（例如频繁后台轮询推送、自动并发多 Git worktree、深层前端 RPC 劫持或无节制长循环自动续跑）不仅会放大维护复杂度，也更容易触发上游网页端风控。因此当前刻意保留边界清晰、低侵入的轻量实现，并将以下已知不足与取舍公开列明，供有重度定制需求的开发者按需扩展：

1. **权限拦截保持轻量本机桥控（故意不做重型沙箱）**：
   - `security.py` 的 `check_exec` 仅基于规则与正则表达式识别脚本中的明显外写路径，不做 AST 级子命令解析、网络出站防火墙或容器/沙箱虚拟化；如需企业级强隔离，建议自行外包一层容器或修改 `security.py` 扩展审批规则。
2. **快照只备份，未暴露事务级自动回滚与文件乐观并发锁**：
   - 每次覆盖写入与替换都会自动在 `.mcp_snapshots/` 保留最多 20 份 `.bak` 备份，但默认未提供跨多文件批量回滚工具，也未对多会话绑定同一目录施加文件 mtime/SHA 乐观并发锁；多人/多标签同时修改同一项目目录时需由使用者自行错开。
3. **后台作业与桥接队列为轻量内存态**：
   - 权限策略、规则配置、工作区绑定与 `task_plan` 会落盘持久化；但正在运行中的 `start_job` 子进程及待消费的媒体上传/下载任务仅驻留内存，服务端进程重启后进行中的作业需重新发起。
4. **受限于 Gemini Web 宿主的先天能力边界**：
   - 网页端不支持接收 MCP 实时 `notifications/progress`，用户在网页点击「停止生成」也无法自动向后端已拉起的同步 `powershell`/`python`/`bash` 进程发送中断信号（长任务仍建议走 `start_job`）。
   - 若多标签页**同时处于生成中**触发来源歧义，`ALWAYS_ALLOWED_TOOLS`（如 `workspace_status`）等免审批只读探活会回退至服务端默认工作区。
   - `workspace_rules` 依赖工具调用尾部注入，若整轮纯文本推理未调用任何工具则不会触发规则重锚。

---

## 7. 运行自检测试

```powershell
python -m unittest discover -s tests -v
```
