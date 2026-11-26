// ==UserScript==
// @name         pc-work-mcp Gemini Bridge
// @namespace    https://pc-work-mcp.local/
// @version      1.2.0
// @description  连接 Gemini 网页端与本地 pc-work-mcp：实时同步会话 ID（含首轮异步捕获）、监听文件上传完成自动发送、将网页端生成的图片/视频/音乐下载落盘到指定目录。
// @match        https://gemini.google.com/*
// @grant        GM_xmlhttpRequest
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_registerMenuCommand
// @grant        GM_openInTab
// @grant        unsafeWindow
// @connect      127.0.0.1
// @connect      localhost
// @connect      *
// @noframes
// @run-at       document-idle
// ==/UserScript==

(function () {
  'use strict';

  // 严禁在同源隐藏 iframe（如 https://gemini.google.com/_/bscframe）中运行，避免共享 sessionStorage 覆盖会话 ID
  if (window.top !== window.self) return;
  if (location.pathname.startsWith('/_/')) return;

  // 若通过 /bridge/pc-work-mcp-gemini.user.js?token=... 安装，服务端会自动填入本机地址与 Token
  const EMBEDDED_BASE_URL = "__PC_WORK_MCP_BASE_URL__";
  const EMBEDDED_TOKEN = "__PC_WORK_MCP_TOKEN__";

  const KEY_BASE_URL = 'pc_work_mcp_base_url';
  const KEY_TOKEN = 'pc_work_mcp_token';
  const TAB_ID_KEY = 'pc_work_mcp_tab_id';

  function getTabId() {
    let tid = sessionStorage.getItem(TAB_ID_KEY);
    if (!tid) {
      tid = 'tab_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
      sessionStorage.setItem(TAB_ID_KEY, tid);
    }
    return tid;
  }

  function getBaseUrl() {
    const saved = String(GM_getValue(KEY_BASE_URL, '') || '').trim();
    if (saved) return saved.replace(/\/+$/, '');
    if (EMBEDDED_BASE_URL && !EMBEDDED_BASE_URL.includes('__PC_WORK_MCP')) {
      return EMBEDDED_BASE_URL.replace(/\/+$/, '');
    }
    return 'http://127.0.0.1:15672';
  }

  function getToken() {
    const saved = String(GM_getValue(KEY_TOKEN, '') || '').trim();
    if (saved) return saved;
    if (EMBEDDED_TOKEN && !EMBEDDED_TOKEN.includes('__PC_WORK_MCP')) {
      return EMBEDDED_TOKEN.trim();
    }
    return '';
  }

  const TAB_ID = getTabId();
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // -------------------------------------------------------------------------
  // 网络监听：追踪原生上传并发计数与生成产物 CDN URL
  // -------------------------------------------------------------------------
  let inflightUploads = 0;
  let lastUploadDoneAt = 0;
  const recentMediaUrls = [];
  const blobUrlCache = new Map();

  function cacheBlobUrl(blobUrl, obj) {
    try {
      if (!blobUrl || !(obj instanceof Blob)) return;
      if (!/^(image|video|audio)\//i.test(obj.type || '') && obj.size < 10240) return;
      blobUrlCache.set(blobUrl, obj);
      if (blobUrlCache.size > 15) {
        const oldest = blobUrlCache.keys().next().value;
        blobUrlCache.delete(oldest);
      }
    } catch {}
  }

  function pushRecentMediaUrl(url, kindHint) {
    if (!url || typeof url !== 'string') return;
    if (
      !/googleusercontent\.com\/(gg-dl|rd-gg-dl)|work\.fife\.usercontent\.google\.com|contribution\.usercontent\.google\.com\/download/i.test(
        url
      )
    ) {
      return;
    }
    recentMediaUrls.push({ url, kindHint: kindHint || 'auto', ts: Date.now() });
    if (recentMediaUrls.length > 30) recentMediaUrls.shift();
  }

  function scanTextForMediaUrls(text) {
    if (!text || typeof text !== 'string') return;
    const normalized = text
      .replace(/\\\//g, '/')
      .replace(/\\u003d/gi, '=')
      .replace(/\\u0026/gi, '&');
    const re = /https:\/\/(?:lh3\.googleusercontent\.com\/(?:gg-dl|rd-gg-dl)|work\.fife\.usercontent\.google\.com|contribution\.usercontent\.google\.com\/download)[^\s"'\\<>]+/g;
    let m;
    while ((m = re.exec(normalized)) !== null) {
      pushRecentMediaUrl(m[0], 'auto');
    }
  }

  function hookNetwork() {
    const win = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;
    if (win.__pcWorkMcpHooked) return;
    win.__pcWorkMcpHooked = true;

    const isUploadUrl = (u) => /push\.clients6\.google\.com\/upload/i.test(String(u || ''));

    if (win.URL && typeof win.URL.createObjectURL === 'function') {
      const origCreateObjectUrl = win.URL.createObjectURL.bind(win.URL);
      win.URL.createObjectURL = function (obj) {
        const resUrl = origCreateObjectUrl(obj);
        cacheBlobUrl(resUrl, obj);
        return resUrl;
      };
    }

    const origFetch = win.fetch;
    if (typeof origFetch === 'function') {
      win.fetch = function (...args) {
        const reqUrl = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
        const tracked = isUploadUrl(reqUrl);
        if (tracked) inflightUploads++;
        return origFetch.apply(this, args).then(
          (resp) => {
            if (tracked) {
              inflightUploads = Math.max(0, inflightUploads - 1);
              lastUploadDoneAt = Date.now();
            }
            try {
              if (/StreamGenerate|batchexecute|processSession/i.test(reqUrl) && resp && resp.clone) {
                resp.clone().text().then(scanTextForMediaUrls).catch(() => {});
              }
            } catch {}
            return resp;
          },
          (err) => {
            if (tracked) {
              inflightUploads = Math.max(0, inflightUploads - 1);
              lastUploadDoneAt = Date.now();
            }
            throw err;
          }
        );
      };
    }

    const OrigXHR = win.XMLHttpRequest;
    if (OrigXHR && OrigXHR.prototype) {
      const origOpen = OrigXHR.prototype.open;
      const origSend = OrigXHR.prototype.send;
      OrigXHR.prototype.open = function (method, url, ...rest) {
        this.__pcWorkMcpUrl = String(url || '');
        return origOpen.call(this, method, url, ...rest);
      };
      OrigXHR.prototype.send = function (...args) {
        const tracked = isUploadUrl(this.__pcWorkMcpUrl);
        if (tracked) {
          inflightUploads++;
          this.addEventListener(
            'loadend',
            () => {
              inflightUploads = Math.max(0, inflightUploads - 1);
              lastUploadDoneAt = Date.now();
            },
            { once: true }
          );
        } else if (/StreamGenerate|batchexecute|processSession/i.test(this.__pcWorkMcpUrl || '')) {
          this.addEventListener(
            'load',
            () => {
              try {
                if (typeof this.responseText === 'string') scanTextForMediaUrls(this.responseText);
              } catch {}
            },
            { once: true }
          );
        }
        return origSend.apply(this, args);
      };
    }
  }

  // -------------------------------------------------------------------------
  // GM_xmlhttpRequest 封装（绕开页面 CSP 与 Mixed Content 限制访问本机 MCP）
  // -------------------------------------------------------------------------
  function gmRequest({ method = 'GET', url, headers = {}, data = undefined, responseType = 'json', timeout = 30000 }) {
    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        method,
        url,
        headers,
        data,
        responseType,
        timeout,
        onload: (res) => {
          if (res.status >= 200 && res.status < 300) {
            if (responseType === 'json') {
              try {
                resolve(res.response !== undefined && res.response !== null ? res.response : JSON.parse(res.responseText || '{}'));
              } catch {
                resolve({});
              }
            } else {
              resolve(res);
            }
          } else {
            reject(new Error(`HTTP ${res.status}: ${(res.responseText || '').slice(0, 160)}`));
          }
        },
        onerror: (err) => reject(new Error(err?.error || 'network error')),
        ontimeout: () => reject(new Error('request timeout')),
      });
    });
  }

  function mcpJson(method, path, bodyObj) {
    const token = getToken();
    if (!token) return Promise.reject(new Error('未配置 MCP Auth Token'));
    const headers = {
      Authorization: 'Bearer ' + token,
    };
    let data;
    if (bodyObj !== undefined) {
      headers['Content-Type'] = 'application/json';
      data = JSON.stringify(bodyObj);
    }
    return gmRequest({
      method,
      url: getBaseUrl() + path,
      headers,
      data,
      responseType: 'json',
    });
  }

  function mcpDownloadBuffer(path) {
    const token = getToken();
    return gmRequest({
      method: 'GET',
      url: getBaseUrl() + path,
      headers: { Authorization: 'Bearer ' + token },
      responseType: 'arraybuffer',
      timeout: 120000,
    }).then((res) => res.response);
  }

  function mcpUploadArtifact(taskId, index, filename, mimeType, buffer) {
    const token = getToken();
    const qs =
      `task_id=${encodeURIComponent(taskId)}&index=${encodeURIComponent(String(index))}` +
      `&filename=${encodeURIComponent(filename)}&mime=${encodeURIComponent(mimeType || 'application/octet-stream')}`;
    const blob = new Blob([buffer], { type: mimeType || 'application/octet-stream' });
    return gmRequest({
      method: 'POST',
      url: `${getBaseUrl()}/bridge/task_upload?${qs}`,
      headers: {
        Authorization: 'Bearer ' + token,
        'Content-Type': mimeType || 'application/octet-stream',
      },
      data: blob,
      responseType: 'json',
      timeout: 120000,
    });
  }

  // -------------------------------------------------------------------------
  // Gemini 会话 ID & DOM 探测工具（全量基于 createElement，严禁 innerHTML）
  // -------------------------------------------------------------------------
  function getConversationId() {
    const m = location.pathname.match(/^\/app\/([a-f0-9]{6,64})/i);
    if (m) return m[1];
    // 首轮刚发出时侧边栏可能先于地址栏高亮出新会话链接
    const hasTurns = document.querySelectorAll('user-query, model-response').length > 0;
    if (hasTurns) {
      const activeNav = document.querySelector('a[href*="/app/"].is-active, a[href*="/app/"].mdc-list-item--activated');
      if (activeNav) {
        const href = activeNav.getAttribute('href') || '';
        const m2 = href.match(/\/app\/([a-f0-9]{6,64})/i);
        if (m2) return m2[1];
      }
    }
    return null;
  }

  function getEditorBox() {
    return document.querySelector(
      'rich-textarea .ql-editor, div[contenteditable="true"][role="textbox"], rich-textarea textarea'
    );
  }

  function findSendButton() {
    const btns = Array.from(document.querySelectorAll('input-area-v2 button, chat-window button'));
    return btns.find((b) => {
      const icon = b.querySelector('mat-icon')?.getAttribute('fonticon') || b.querySelector('mat-icon')?.textContent?.trim();
      const aria = b.getAttribute('aria-label') || '';
      return icon === 'arrow_upward' || icon === 'send' || /发送|Send message|Send/i.test(aria);
    }) || null;
  }

  function findStopButton() {
    const btns = Array.from(document.querySelectorAll('input-area-v2 button, chat-window button'));
    return btns.find((b) => {
      const icon = b.querySelector('mat-icon')?.getAttribute('fonticon') || b.querySelector('mat-icon')?.textContent?.trim();
      const aria = b.getAttribute('aria-label') || '';
      return icon === 'stop' || icon === 'stop_circle' || /停止回答|停止|Stop generating|Stop response/i.test(aria);
    }) || null;
  }

  function isGenerating() {
    if (findStopButton()) return true;
    const lastResp = Array.from(document.querySelectorAll('model-response')).pop();
    if (lastResp) {
      if (lastResp.querySelector('[aria-busy="true"], .response-streaming, mat-progress-bar')) return true;
    }
    return false;
  }

  function findPlusButton() {
    const btns = Array.from(document.querySelectorAll('input-area-v2 button, chat-window button'));
    return btns.find((b) => {
      const icon = b.querySelector('mat-icon')?.getAttribute('fonticon') || b.querySelector('mat-icon')?.textContent?.trim();
      const aria = b.getAttribute('aria-label') || '';
      return icon === 'plus' || /上传和工具|Upload|Add/i.test(aria);
    }) || null;
  }

  function closeOverlays() {
    const backdrop = document.querySelector('.cdk-overlay-backdrop');
    if (backdrop) backdrop.click();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', keyCode: 27, bubbles: true }));
  }

  async function selectToolMode(mode) {
    const labelMap = {
      image: /制作图片|Create image/i,
      video: /制作视频|Create video/i,
      music: /制作音乐|Create music/i,
    };
    const re = labelMap[mode];
    if (!re) return false;
    const plusBtn = findPlusButton();
    if (!plusBtn) return false;
    plusBtn.click();
    await sleep(350);
    const items = Array.from(document.querySelectorAll('.cdk-overlay-container gem-menu-item, .cdk-overlay-container [role="menuitemcheckbox"]'));
    const target = items.find((el) => re.test((el.innerText || el.getAttribute('aria-label') || '').trim()));
    if (target) {
      const checked = target.getAttribute('aria-checked') === 'true';
      if (!checked) target.click();
      await sleep(250);
      return true;
    }
    closeOverlays();
    return false;
  }

  async function attachFilesToGemini(fileObjs) {
    const mediaFiles = [];
    const docFiles = [];
    for (const f of fileObjs) {
      if (/^(image|video)\//i.test(f.type)) mediaFiles.push(f);
      else docFiles.push(f);
    }

    const injectViaHiddenInputs = async () => {
      const plusBtn = findPlusButton();
      if (plusBtn) {
        plusBtn.click();
        await sleep(350);
      }
      const inputs = Array.from(document.querySelectorAll('input.hidden-file-input, input[type="file"]'));
      let matched = 0;

      if (mediaFiles.length > 0) {
        const mediaInput = inputs.find((inp) => /image\/\*|video\/\*/i.test(inp.accept || '')) || inputs[0];
        if (mediaInput) {
          const dt = new DataTransfer();
          mediaFiles.forEach((f) => dt.items.add(f));
          mediaInput.files = dt.files;
          mediaInput.dispatchEvent(new Event('change', { bubbles: true }));
          matched += mediaFiles.length;
        }
      }

      if (docFiles.length > 0) {
        const docInput = inputs.find((inp) => /\.pdf|\.txt/i.test(inp.accept || '')) || inputs[0];
        if (docInput) {
          const dt = new DataTransfer();
          docFiles.forEach((f) => dt.items.add(f));
          docInput.files = dt.files;
          docInput.dispatchEvent(new Event('change', { bubbles: true }));
          matched += docFiles.length;
        }
      }

      await sleep(200);
      closeOverlays();
      return matched;
    };

    const viaInput = await injectViaHiddenInputs();
    if (viaInput >= fileObjs.length) return;

    // 兜底：对图片直接走 paste 事件
    const box = getEditorBox();
    if (!box) throw new Error('未找到 Gemini 输入框');
    box.focus();
    const dt = new DataTransfer();
    fileObjs.forEach((f) => dt.items.add(f));
    box.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: dt }));
  }

  async function waitForUploadComplete(expectedCount, maxWaitMs = 120000) {
    const start = Date.now();
    let stableSince = 0;

    while (Date.now() - start < maxWaitMs) {
      const chips = document.querySelectorAll(
        '.text-input-field uploader-file-preview, .text-input-field gem-media-attachment'
      ).length;
      const busyNodes = document.querySelectorAll(
        '.text-input-field mat-progress-spinner, .text-input-field mat-progress-bar, .text-input-field [role="progressbar"], .text-input-field [aria-busy="true"], .text-input-field .uploading'
      ).length;
      const sendBtn = findSendButton();
      const sendReady = !!sendBtn && !sendBtn.disabled && sendBtn.getAttribute('aria-disabled') !== 'true';
      const uploadIdle = inflightUploads === 0 && (Date.now() - lastUploadDoneAt > 350 || lastUploadDoneAt === 0);

      if (chips >= expectedCount && busyNodes === 0 && uploadIdle && sendReady) {
        if (!stableSince) stableSince = Date.now();
        if (Date.now() - stableSince >= 650) {
          return true;
        }
      } else {
        stableSince = 0;
      }
      await sleep(250);
    }
    throw new Error('等待附件上传完成超时');
  }

  async function insertPromptText(promptText) {
    if (!promptText) return;
    const box = getEditorBox();
    if (!box) throw new Error('未找到 Gemini 输入框');
    const textVal = String(promptText);
    const norm = (s) => String(s || '').replace(/\u200b/g, '').trim();
    const isTextArea = box.tagName === 'TEXTAREA' || box.tagName === 'INPUT';
    const before = isTextArea ? norm(box.value) : norm(box.textContent);

    box.focus();
    try {
      document.execCommand('insertText', false, textVal);
    } catch (_) {}

    const afterExec = isTextArea ? norm(box.value) : norm(box.textContent);
    const probe = norm(textVal).slice(0, 24);
    const insertedOk =
      afterExec !== before && (!probe || afterExec.includes(probe));

    if (!insertedOk) {
      if (isTextArea) {
        box.value = before ? `${box.value}\n${textVal}` : textVal;
      } else {
        // Gemini Web enforces TrustedHTML: create <p> via DOM APIs without touching innerHTML.
        if (before === '' || (box.classList && box.classList.contains('ql-blank'))) {
          while (box.firstChild) box.removeChild(box.firstChild);
        }
        const frag = document.createDocumentFragment();
        const lines = textVal.split(/\r?\n/);
        for (const line of lines) {
          const p = document.createElement('p');
          if (line === '') {
            p.appendChild(document.createElement('br'));
          } else {
            p.textContent = line;
          }
          frag.appendChild(p);
        }
        box.appendChild(frag);
        if (box.classList) box.classList.remove('ql-blank');
      }
      try {
        box.dispatchEvent(new InputEvent('input', { bubbles: true, data: textVal, inputType: 'insertText' }));
      } catch (_) {
        box.dispatchEvent(new Event('input', { bubbles: true }));
      }
      box.dispatchEvent(new Event('change', { bubbles: true }));
      box.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: ' ' }));
    } else {
      box.dispatchEvent(new Event('input', { bubbles: true }));
    }
    await sleep(250);
  }

  async function clickSendOnce() {
    for (let i = 0; i < 15; i++) {
      const btn = findSendButton();
      if (btn && !btn.disabled && btn.getAttribute('aria-disabled') !== 'true') {
        btn.click();
        return true;
      }
      await sleep(200);
    }
    throw new Error('发送按钮不可用或未就绪');
  }

  // -------------------------------------------------------------------------
  // 产物提取（图片 / 视频 / 音乐）
  // -------------------------------------------------------------------------
  function normalizeGoogleImageUrl(url) {
    if (!url) return url;
    if (/lh3\.googleusercontent\.com/i.test(url)) {
      if (/=[sw]\d+[^/?#]*$/i.test(url)) {
        return url.replace(/=[sw]\d+[^/?#]*$/i, '=s0');
      }
      if (!/=s0($|\?)/i.test(url)) {
        return url.includes('?') ? url.replace(/\?/, '=s0?') : url + '=s0';
      }
    }
    return url;
  }

  function extractMediaFromResponseEl(respEl, kind) {
    const out = [];
    const seen = new Set();
    const addCandidate = (url, mediaType, nameHint, el = null) => {
      if (!url || seen.has(url)) return;
      seen.add(url);
      out.push({ url, mediaType, nameHint, el });
    };
    if (!respEl) return out;

    if (kind === 'auto' || kind === 'image') {
      const imgs = Array.from(
        respEl.querySelectorAll('generated-image img, single-image img, img')
      ).filter((img) => {
        const src = img.currentSrc || img.src || '';
        const cls = String(img.className || '');
        if (!src) return false;
        if (/sparkle-image|mavatar-image|user-icon|avatar/i.test(cls)) return false;
        if (/gstatic\.com\/lamda\/images\/gemini_sparkle/i.test(src)) return false;
        if (!img.complete) return false;
        return img.naturalWidth >= 128 || /gg-dl|rd-gg-dl|work\.fife\.usercontent|^blob:|^data:image\//i.test(src);
      });
      imgs.forEach((img, idx) => {
        const rawUrl = img.currentSrc || img.src || '';
        addCandidate(normalizeGoogleImageUrl(rawUrl), 'image', `gemini_image_${idx}.png`, img);
      });
    }

    if (kind === 'auto' || kind === 'video') {
      const videos = Array.from(respEl.querySelectorAll('video, video source'));
      videos.forEach((v, idx) => {
        const src = v.currentSrc || v.src || v.getAttribute('src') || '';
        if (src) addCandidate(src, 'video', `gemini_video_${idx}.mp4`);
      });
    }

    if (kind === 'auto' || kind === 'music') {
      const audios = Array.from(respEl.querySelectorAll('audio, audio source'));
      audios.forEach((a, idx) => {
        const src = a.currentSrc || a.src || a.getAttribute('src') || '';
        if (src) addCandidate(src, 'music', `gemini_music_${idx}.mp3`);
      });
    }

    const links = Array.from(respEl.querySelectorAll('a[href]'));
    links.forEach((a, idx) => {
      const href = a.href || '';
      if (/contribution\.usercontent\.google\.com\/download|lh3\.googleusercontent\.com\/gg-dl/i.test(href)) {
        addCandidate(normalizeGoogleImageUrl(href), kind === 'auto' ? 'media' : kind, `gemini_artifact_${idx}`);
      }
    });
    return out;
  }

  function collectGeneratedMedia(kind, taskStartedAt, minRespIndex = 0, allowHistoryScan = true) {
    const resps = Array.from(document.querySelectorAll('model-response'));
    if (resps.length > minRespIndex) {
      if (allowHistoryScan) {
        // 从最新一条回答往前找最近一条包含生成产物的 model-response（兼容“先生成图，下一轮再调用保存工具”）
        for (let i = resps.length - 1; i >= minRespIndex; i--) {
          const found = extractMediaFromResponseEl(resps[i], kind);
          if (found.length > 0) return found;
        }
      } else {
        // 若本次由 trigger_prompt 主动触发了新一轮生成，只扫描新产生的回复节点
        for (let i = resps.length - 1; i >= minRespIndex; i--) {
          const found = extractMediaFromResponseEl(resps[i], kind);
          if (found.length > 0) return found;
        }
      }
    }

    const out = [];
    const seen = new Set();
    for (const item of recentMediaUrls) {
      if (item.ts >= taskStartedAt - 15000 && !seen.has(item.url)) {
        seen.add(item.url);
        out.push({ url: normalizeGoogleImageUrl(item.url), mediaType: kind, nameHint: 'gemini_artifact' });
      }
    }
    return out;
  }

  async function extractImageViaCanvas(imgEl, targetPathHint = '') {
    if (!imgEl || !imgEl.naturalWidth || !imgEl.naturalHeight) {
      throw new Error('image element not loaded');
    }
    const canvas = document.createElement('canvas');
    canvas.width = imgEl.naturalWidth;
    canvas.height = imgEl.naturalHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(imgEl, 0, 0);
    const wantJpeg = /\.jpe?g$/i.test(String(targetPathHint || ''));
    const mime = wantJpeg ? 'image/jpeg' : 'image/png';
    const blob = await new Promise((res) => canvas.toBlob(res, mime, wantJpeg ? 0.95 : undefined));
    if (!blob) throw new Error('canvas.toBlob returned null');
    return { buf: await blob.arrayBuffer(), mime: blob.type || mime };
  }

  async function fetchMediaBytes(candidate, targetPathHint = '') {
    const url = typeof candidate === 'string' ? candidate : candidate.url;
    const el = typeof candidate === 'object' ? candidate.el : null;

    if (blobUrlCache.has(url)) {
      const cachedBlob = blobUrlCache.get(url);
      return { buf: await cachedBlob.arrayBuffer(), mime: cachedBlob.type || '' };
    }

    if (url.startsWith('blob:') || url.startsWith('data:')) {
      try {
        const pageFetch = (typeof unsafeWindow !== 'undefined' && typeof unsafeWindow.fetch === 'function')
          ? unsafeWindow.fetch.bind(unsafeWindow)
          : fetch;
        const resp = await pageFetch(url);
        if (!resp.ok) throw new Error(`blob/data fetch failed: ${resp.status}`);
        const mime = resp.headers.get('content-type') || '';
        const buf = await resp.arrayBuffer();
        return { buf, mime };
      } catch (err) {
        if (el && el.tagName === 'IMG') {
          return await extractImageViaCanvas(el, targetPathHint);
        }
        throw err;
      }
    }
    const res = await gmRequest({
      method: 'GET',
      url,
      responseType: 'arraybuffer',
      timeout: 120000,
    });
    let mime = '';
    const m = /content-type:\s*([^\r\n;]+)/i.exec(res.responseHeaders || '');
    if (m) mime = m[1].trim();
    return { buf: res.response, mime };
  }

  // -------------------------------------------------------------------------
  // 任务执行器
  // -------------------------------------------------------------------------
  let taskRunning = false;

  async function runUploadMediaTask(task) {
    setPillStatus('等待回合结束...', '#f59e0b');
    const waitGenStart = Date.now();
    while (isGenerating() && Date.now() - waitGenStart < 120000) {
      await sleep(300);
    }
    await sleep((task.delay_sec || 2) * 1000);

    setPillStatus(`拉取 ${task.files.length} 个文件...`, '#3b82f6');
    const fileObjs = [];
    for (const spec of task.files) {
      const buf = await mcpDownloadBuffer(`/bridge/file/${encodeURIComponent(task.task_id)}/${spec.index}`);
      fileObjs.push(new File([buf], spec.name, { type: spec.mime || 'application/octet-stream' }));
    }

    if (task.tool_mode && task.tool_mode !== 'none') {
      await selectToolMode(task.tool_mode);
    }

    setPillStatus('上传媒体到会话...', '#3b82f6');
    await attachFilesToGemini(fileObjs);
    await waitForUploadComplete(fileObjs.length, 150000);

    if (task.prompt) {
      await insertPromptText(task.prompt);
    }

    if (task.auto_send !== false) {
      setPillStatus('上传完成，自动发送...', '#10b981');
      await clickSendOnce();
    }

    await mcpJson('POST', '/bridge/task_result', {
      task_id: task.task_id,
      status: 'completed',
      conversation_id: getConversationId(),
      result: { uploaded_count: fileObjs.length, auto_send: task.auto_send !== false },
    });
    setPillStatus('上传并发送完成', '#10b981');
  }

  async function runSaveMediaTask(task) {
    const taskStartedAt = Date.now();
    setPillStatus('等待回合停稳...', '#f59e0b');
    const waitStop0 = Date.now();
    while (isGenerating() && Date.now() - waitStop0 < 120000) {
      await sleep(300);
    }
    await sleep((task.delay_sec || 2) * 1000);

    let minRespIndex = 0;
    const hasTrigger = Boolean(task.trigger_prompt);
    if (hasTrigger) {
      setPillStatus('发起生成请求...', '#3b82f6');
      if (task.media_kind && task.media_kind !== 'auto') {
        await selectToolMode(task.media_kind);
      }
      await insertPromptText(task.trigger_prompt);
      const prevCount = document.querySelectorAll('model-response').length;
      minRespIndex = prevCount;
      await clickSendOnce();

      // 等待新回复开始并完成
      const startWait = Date.now();
      while (Date.now() - startWait < 30000) {
        if (isGenerating() || document.querySelectorAll('model-response').length > prevCount) break;
        await sleep(250);
      }
    }

    setPillStatus('等待生成产物就绪...', '#3b82f6');
    const deadline = Date.now() + (task.timeout_sec || 240) * 1000;
    let candidates = [];
    while (Date.now() < deadline) {
      if (!isGenerating()) {
        candidates = collectGeneratedMedia(task.media_kind || 'auto', taskStartedAt, minRespIndex, !hasTrigger);
        if (candidates.length > 0) {
          await sleep(800);
          candidates = collectGeneratedMedia(task.media_kind || 'auto', taskStartedAt, minRespIndex, !hasTrigger);
          break;
        }
      }
      await sleep(500);
    }

    if (candidates.length === 0) {
      throw new Error('未在当前回答中检测到可下载的图片/视频/音乐产物');
    }

    setPillStatus(`下载 ${candidates.length} 个产物落盘...`, '#3b82f6');
    const saved = [];
    for (let i = 0; i < candidates.length; i++) {
      const c = candidates[i];
      const { buf, mime } = await fetchMediaBytes(c, task.target_path || '');
      if (!buf || buf.byteLength === 0) continue;
      const up = await mcpUploadArtifact(task.task_id, i, c.nameHint, mime, buf);
      if (up && up.saved) saved.push(up.saved);
    }

    if (saved.length === 0) {
      throw new Error('产物下载字节为空');
    }

    await mcpJson('POST', '/bridge/task_result', {
      task_id: task.task_id,
      status: 'completed',
      conversation_id: getConversationId(),
      result: { saved_files: saved },
    });
    setPillStatus(`已保存 ${saved.length} 个文件`, '#10b981');
  }

  let continueChipEl = null;
  let activeContinueCancelled = false;

  function removeContinueChip() {
    if (continueChipEl) {
      continueChipEl.remove();
      continueChipEl = null;
    }
  }

  function showContinueChip(turnLabel, remainingSec, onCancel) {
    removeContinueChip();
    if (!document.body) return;
    const chip = document.createElement('div');
    chip.id = 'pc-work-mcp-continue-chip';
    Object.assign(chip.style, {
      position: 'fixed',
      bottom: '44px',
      right: '16px',
      zIndex: '100000',
      display: 'inline-flex',
      alignItems: 'center',
      gap: '8px',
      padding: '6px 10px',
      borderRadius: '8px',
      background: '#18181b',
      color: '#fde68a',
      border: '1px solid #f59e0b',
      fontSize: '12px',
      fontFamily: 'system-ui, sans-serif',
      boxShadow: '0 4px 14px rgba(0,0,0,0.45)',
    });
    const txt = document.createElement('span');
    txt.textContent = `⏳ 自动续跑 ${turnLabel} (${remainingSec}s)`;
    const btn = document.createElement('button');
    btn.textContent = '⏸ 暂停取消';
    Object.assign(btn.style, {
      padding: '3px 8px',
      borderRadius: '5px',
      border: 'none',
      background: '#dc2626',
      color: '#ffffff',
      fontSize: '11px',
      cursor: 'pointer',
    });
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = '已取消';
      await onCancel();
    });
    chip.appendChild(txt);
    chip.appendChild(btn);
    document.body.appendChild(chip);
    continueChipEl = chip;
    return txt;
  }

  async function runContinueTurnTask(task) {
    activeContinueCancelled = false;
    const turnLabel = `#${task.turn_index || 1}/${task.max_auto_turns || 5}`;
    setPillStatus(`续跑准备 ${turnLabel}...`, '#f59e0b');

    const waitGenStart = Date.now();
    while (isGenerating() && Date.now() - waitGenStart < 120000) {
      if (activeContinueCancelled) break;
      await sleep(300);
    }

    const baseDelay = Math.max(5, Number(task.delay_sec || 8));
    const jitter = Math.floor(Math.random() * (Math.max(0, Number(task.jitter_max_sec || 3)) + 1));
    const totalWaitSec = baseDelay + jitter;

    const doCancel = async () => {
      activeContinueCancelled = true;
      try {
        await mcpJson('POST', '/bridge/task_plan', {
          action: 'stop',
          conversation_id: getConversationId(),
          tab_id: TAB_ID,
          reason: 'cancelled_by_user_chip',
        });
      } catch {}
    };

    const txtEl = showContinueChip(turnLabel, totalWaitSec, doCancel);
    const waitDeadline = Date.now() + totalWaitSec * 1000;
    try {
      while (Date.now() < waitDeadline) {
        if (activeContinueCancelled || (currentTaskPlan && currentTaskPlan.status === 'stopped')) {
          await mcpJson('POST', '/bridge/task_result', {
            task_id: task.task_id,
            status: 'cancelled',
            conversation_id: getConversationId(),
            error: 'cancelled_by_user',
          });
          setPillStatus('已暂停自动续跑', '#71717a');
          return;
        }
        const rem = Math.max(1, Math.ceil((waitDeadline - Date.now()) / 1000));
        if (txtEl) txtEl.textContent = `⏳ 自动续跑 ${turnLabel} (${rem}s)`;
        setPillStatus(`续跑 ${turnLabel} (${rem}s)`, '#3b82f6');
        await sleep(350);
      }

      // 再次检查生成状态与服务端计划状态，避免竞态
      if (activeContinueCancelled || isGenerating()) {
        throw new Error(activeContinueCancelled ? 'cancelled_by_user' : 'browser_still_generating');
      }
      const latestPlanResp = await mcpJson('POST', '/bridge/task_plan', {
        action: 'get',
        conversation_id: getConversationId(),
        tab_id: TAB_ID,
      }).catch(() => null);
      if (latestPlanResp && latestPlanResp.plan && ['stopped', 'completed', 'paused'].includes(latestPlanResp.plan.status)) {
        await mcpJson('POST', '/bridge/task_result', {
          task_id: task.task_id,
          status: 'cancelled',
          conversation_id: getConversationId(),
          error: `plan_${latestPlanResp.plan.status}`,
        });
        setPillStatus('续跑已取消', '#71717a');
        return;
      }

      setPillStatus(`唤醒续跑 ${turnLabel}...`, '#10b981');
      await insertPromptText(task.prompt);
      await clickSendOnce();

      await mcpJson('POST', '/bridge/task_result', {
        task_id: task.task_id,
        status: 'completed',
        conversation_id: getConversationId(),
        result: { turn_index: task.turn_index, sent_chars: (task.prompt || '').length },
      });
      setPillStatus(`已续跑 ${turnLabel}`, '#10b981');
    } finally {
      removeContinueChip();
    }
  }

  // -------------------------------------------------------------------------
  // 心跳 & 轮询 & 权限状态同步 & URL 变更监听
  // -------------------------------------------------------------------------
  let lastReportedCid = null;
  let lastReportedGen = null;
  let lastErrorMsg = '';
  let bridgeConnected = false;
  let currentPolicy = null;
  let currentRulesStatus = null;
  let currentWorkspace = null;
  let currentTaskPlan = null;
  let activeApprovals = [];
  let activeIgnoreSuggestions = [];
  let refreshOpenModalIgnoredFn = null;

  const PROFILE_SHORT = {
    ask: '询问',
    deny: '已禁',
    readonly: '只读',
    media_only: '媒体',
    workspace: '工作区',
    full: '完全',
    custom: '自定',
  };

  const PROFILE_PRESETS = [
    { id: 'ask', label: '按需询问', caps: [] },
    { id: 'readonly', label: '仅只读', caps: ['read'] },
    { id: 'media_only', label: '仅媒体桥接', caps: ['read', 'bridge_read', 'bridge_save'] },
    { id: 'workspace', label: '工作区读写', caps: ['read', 'write', 'bridge_read', 'bridge_save'] },
    { id: 'full', label: '完全工作台', caps: ['read', 'write', 'exec', 'bridge_read', 'bridge_save'] },
    { id: 'deny', label: '全部禁止', caps: [] },
  ];

  const CAP_OPTIONS = [
    { id: 'read', label: '读取文件/图片/目录与推送下载' },
    { id: 'write', label: '写入/编辑工作区与任务计划' },
    { id: 'exec', label: '执行命令 (PS/Python/Bash)' },
    { id: 'bridge_read', label: '桥接上传本机媒体' },
    { id: 'bridge_save', label: '桥接保存网页生成媒体' },
  ];

  function handleBridgeMeta(resp) {
    if (!resp || typeof resp !== 'object') return;
    if (Object.prototype.hasOwnProperty.call(resp, 'effective_policy')) {
      currentPolicy = resp.effective_policy || null;
    }
    if (Object.prototype.hasOwnProperty.call(resp, 'rules_status')) {
      currentRulesStatus = resp.rules_status || null;
    }
    if (Object.prototype.hasOwnProperty.call(resp, 'workspace_binding')) {
      currentWorkspace = resp.workspace_binding || null;
    }
    if (Object.prototype.hasOwnProperty.call(resp, 'task_plan')) {
      currentTaskPlan = resp.task_plan || null;
      if (currentTaskPlan && currentTaskPlan.status === 'stopped') {
        activeContinueCancelled = true;
      }
    }
    if (Array.isArray(resp.pending_approvals)) {
      activeApprovals = resp.pending_approvals;
    }
    if (Array.isArray(resp.pending_ignore_suggestions)) {
      activeIgnoreSuggestions = resp.pending_ignore_suggestions;
    }
    syncApprovalCards();
  }

  async function sendHeartbeat(force = false) {
    const token = getToken();
    if (!token) {
      bridgeConnected = false;
      currentPolicy = null;
      activeApprovals = [];
      activeIgnoreSuggestions = [];
      syncApprovalCards();
      updatePill();
      return;
    }
    const cid = getConversationId();
    const gen = isGenerating();
    if (!force && cid === lastReportedCid && gen === lastReportedGen) {
      // still send periodic heartbeat from loop
    }
    lastReportedCid = cid;
    lastReportedGen = gen;
    try {
      const resp = await mcpJson('POST', '/bridge/heartbeat', {
        tab_id: TAB_ID,
        conversation_id: cid,
        url: location.href,
        title: document.title,
        is_generating: gen,
        focused: document.hasFocus(),
      });
      bridgeConnected = true;
      lastErrorMsg = '';
      handleBridgeMeta(resp);
    } catch (err) {
      bridgeConnected = false;
      lastErrorMsg = String(err && err.message ? err.message : err);
    }
    updatePill();
  }

  async function pollTasksOnce() {
    if (!getToken()) return;
    const cid = getConversationId();
    let resp;
    try {
      const qs = `tab_id=${encodeURIComponent(TAB_ID)}` + (cid ? `&conversation_id=${encodeURIComponent(cid)}` : '');
      resp = await mcpJson('GET', `/bridge/tasks?${qs}`);
      bridgeConnected = true;
      lastErrorMsg = '';
      handleBridgeMeta(resp);
      updatePill();
    } catch (err) {
      bridgeConnected = false;
      lastErrorMsg = String(err && err.message ? err.message : err);
      updatePill();
      return;
    }

    if (taskRunning) return;
    const actions = (resp && resp.actions) || [];
    if (actions.length === 0) return;

    const act = actions[0];
    if (act.action === 'open_conversation' && act.url) {
      setPillStatus(`打开会话 ${act.conversation_id.slice(0, 8)}...`, '#3b82f6');
      try {
        GM_openInTab(act.url, { active: true, insert: true });
      } catch {
        location.href = act.url;
      }
      return;
    }

    const task = act.task;
    if (!task) return;
    taskRunning = true;
    try {
      if (act.action === 'upload_media') {
        await runUploadMediaTask(task);
      } else if (act.action === 'save_media') {
        await runSaveMediaTask(task);
      } else if (act.action === 'continue_turn') {
        await runContinueTurnTask(task);
      }
    } catch (err) {
      const msg = String(err && err.message ? err.message : err);
      setPillStatus('任务失败: ' + msg.slice(0, 20), '#ef4444');
      try {
        await mcpJson('POST', '/bridge/task_result', {
          task_id: task.task_id,
          status: 'failed',
          conversation_id: getConversationId(),
          error: msg,
        });
      } catch {}
    } finally {
      taskRunning = false;
      setTimeout(updatePill, 2500);
    }
  }

  function watchNavigation() {
    const win = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;
    const notify = () => {
      const cid = getConversationId();
      const gen = isGenerating();
      if (cid !== lastReportedCid || gen !== lastReportedGen) {
        sendHeartbeat(true);
      }
    };
    const wrapHistory = (fnName) => {
      const orig = win.history[fnName];
      if (typeof orig !== 'function') return;
      win.history[fnName] = function (...args) {
        const ret = orig.apply(this, args);
        setTimeout(notify, 50);
        return ret;
      };
    };
    wrapHistory('pushState');
    wrapHistory('replaceState');
    window.addEventListener('popstate', () => setTimeout(notify, 50));
    setInterval(notify, 400);
  }

  // -------------------------------------------------------------------------
  // 状态浮标与设置弹窗（纯 createElement，兼容 TrustedHTML）
  // -------------------------------------------------------------------------
  let pillEl = null;
  let dotEl = null;
  let labelEl = null;
  let customStatusText = '';
  let customStatusColor = '';

  function setPillStatus(text, color) {
    customStatusText = text || '';
    customStatusColor = color || '';
    updatePill();
    if (text) {
      setTimeout(() => {
        if (customStatusText === text) {
          customStatusText = '';
          customStatusColor = '';
          updatePill();
        }
      }, 6000);
    }
  }

  function updatePill() {
    if (!pillEl || !dotEl || !labelEl) return;
    const token = getToken();
    const cid = getConversationId();
    if (!token) {
      dotEl.style.background = '#f59e0b';
      pillEl.style.borderColor = 'rgba(255,255,255,0.14)';
      labelEl.textContent = 'MCP: 未设Token(点此配置)';
      return;
    }
    if (activeApprovals.length > 0) {
      dotEl.style.background = '#f59e0b';
      pillEl.style.borderColor = '#f59e0b';
      labelEl.textContent = `MCP ⚠ 待审批: ${activeApprovals[0].tool_name}`;
      return;
    }
    pillEl.style.borderColor = 'rgba(255,255,255,0.14)';
    if (customStatusText) {
      dotEl.style.background = customStatusColor || '#3b82f6';
      labelEl.textContent = `MCP: ${customStatusText}`;
      return;
    }
    if (bridgeConnected) {
      const prof = (currentPolicy && currentPolicy.profile) || '';
      const shortTier = PROFILE_SHORT[prof] || '';
      dotEl.style.background = prof === 'deny' ? '#ef4444' : (prof === 'ask' ? '#f59e0b' : '#10b981');
      const baseText = cid ? `MCP ● ${cid.slice(0, 8)}` : 'MCP ● 首轮待ID';
      const wsLabel =
        currentWorkspace && currentWorkspace.is_custom && currentWorkspace.label
          ? String(currentWorkspace.label).slice(0, 12)
          : '';
      const parts = [baseText];
      if (shortTier) parts.push(shortTier);
      if (wsLabel) parts.push(`📁${wsLabel}`);
      if (currentTaskPlan && currentTaskPlan.status === 'active') {
        parts.push(`📋${currentTaskPlan.progress || ''}`);
      }
      labelEl.textContent = parts.join(' · ');
    } else {
      dotEl.style.background = '#ef4444';
      labelEl.textContent = lastErrorMsg ? `MCP ○ 离线` : 'MCP ○ 连接中';
    }
  }

  // -------------------------------------------------------------------------
  // 本地桥接审批弹窗（Shadow DOM 隔离，不由会话内 Agent 或页面 CSS 干扰）
  // -------------------------------------------------------------------------
  let approvalHost = null;
  let approvalRoot = null;
  let approvalSig = '';
  let approvalTickTimer = null;
  const approvalDeadlines = new Map();

  async function submitApprovalDecision(approvalId, payload) {
    try {
      await mcpJson('POST', '/bridge/permissions/decision', {
        approval_id: approvalId,
        conversation_id: getConversationId(),
        tab_id: TAB_ID,
        ...payload,
      });
    } catch (err) {
      setPillStatus('审批提交失败: ' + String(err && err.message ? err.message : err).slice(0, 24), '#ef4444');
    }
    activeApprovals = activeApprovals.filter((a) => a.approval_id !== approvalId);
    syncApprovalCards();
    await sendHeartbeat(true);
  }

  async function submitIgnoreDecision(suggestionId, decision, dirs) {
    try {
      const snap = await mcpJson('POST', '/bridge/ignored_dirs/decision', {
        suggestion_id: suggestionId,
        decision,
        dirs,
      });
      if (decision === 'approve') {
        setPillStatus('已永久写入忽略目录', '#06b6d4');
      }
      if (typeof refreshOpenModalIgnoredFn === 'function' && snap) {
        refreshOpenModalIgnoredFn(snap);
      }
    } catch (err) {
      setPillStatus('保存忽略目录失败: ' + String(err && err.message ? err.message : err).slice(0, 24), '#ef4444');
    }
    activeIgnoreSuggestions = activeIgnoreSuggestions.filter((s) => s.suggestion_id !== suggestionId);
    syncApprovalCards();
    await sendHeartbeat(true);
  }

  function syncApprovalCards() {
    const readySuggestions = !isGenerating() ? (activeIgnoreSuggestions || []) : [];
    const hasApprovals = activeApprovals && activeApprovals.length > 0;
    const hasSuggestions = readySuggestions.length > 0;

    if (!hasApprovals && !hasSuggestions) {
      if (approvalHost) {
        approvalHost.remove();
        approvalHost = null;
        approvalRoot = null;
      }
      approvalSig = '';
      if (approvalTickTimer) {
        clearInterval(approvalTickTimer);
        approvalTickTimer = null;
      }
      approvalDeadlines.clear();
      return;
    }

    const sig =
      (activeApprovals || []).map((a) => a.approval_id).join(',') +
      '|' +
      readySuggestions.map((s) => s.suggestion_id).join(',');
    if (sig === approvalSig && approvalHost && approvalHost.isConnected) {
      return;
    }
    approvalSig = sig;

    if (!approvalHost || !approvalHost.isConnected) {
      approvalHost = document.createElement('div');
      approvalHost.id = 'pc-work-mcp-approval-host';
      Object.assign(approvalHost.style, {
        position: 'fixed',
        bottom: '46px',
        right: '16px',
        zIndex: '100001',
        maxWidth: '410px',
      });
      approvalRoot = typeof approvalHost.attachShadow === 'function'
        ? approvalHost.attachShadow({ mode: 'closed' })
        : approvalHost;
      (document.body || document.documentElement).appendChild(approvalHost);
    }

    while (approvalRoot.firstChild) approvalRoot.removeChild(approvalRoot.firstChild);

    const wrap = document.createElement('div');
    Object.assign(wrap.style, {
      display: 'flex',
      flexDirection: 'column',
      gap: '10px',
      fontFamily: 'system-ui, -apple-system, sans-serif',
    });

    const countdownLabels = [];

    for (const apr of activeApprovals) {
      if (!approvalDeadlines.has(apr.approval_id)) {
        approvalDeadlines.set(apr.approval_id, Date.now() + (apr.remaining_sec || apr.timeout_sec || 45) * 1000);
      }

      const card = document.createElement('div');
      Object.assign(card.style, {
        background: '#18181b',
        color: '#f4f4f5',
        border: '1px solid #f59e0b',
        borderRadius: '12px',
        padding: '14px',
        boxShadow: '0 10px 30px rgba(0,0,0,0.55)',
        fontSize: '12px',
        lineHeight: '1.5',
      });

      const hdr = document.createElement('div');
      Object.assign(hdr.style, {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '8px',
        fontWeight: '600',
        fontSize: '13px',
        color: '#fbbf24',
      });
      const hdrTitle = document.createElement('span');
      hdrTitle.textContent = apr.ambiguous ? '⚠ 多窗口来源歧义 · 本地审批' : '🔐 本窗口权限请求 · 本地桥审批';
      const hdrTimer = document.createElement('span');
      hdrTimer.style.fontSize = '12px';
      hdrTimer.style.color = '#fca5a5';
      const initRem = Math.max(0, Math.ceil((approvalDeadlines.get(apr.approval_id) - Date.now()) / 1000));
      hdrTimer.textContent = `${initRem}s`;
      countdownLabels.push({ id: apr.approval_id, el: hdrTimer });
      hdr.appendChild(hdrTitle);
      hdr.appendChild(hdrTimer);

      const meta = document.createElement('div');
      Object.assign(meta.style, {
        background: '#27272a',
        borderRadius: '8px',
        padding: '8px 10px',
        marginBottom: '10px',
        wordBreak: 'break-all',
      });
      const addMetaLine = (k, v, color = '#e4e4e7') => {
        const row = document.createElement('div');
        const ks = document.createElement('span');
        ks.textContent = k + ': ';
        ks.style.color = '#a1a1aa';
        const vs = document.createElement('span');
        vs.textContent = v;
        vs.style.color = color;
        row.appendChild(ks);
        row.appendChild(vs);
        meta.appendChild(row);
      };
      if (apr.ambiguous) {
        const cands = (apr.candidates || []).map((c) => `${c.title || '(无标题)'} [${(c.conversation_id || c.tab_id || '').slice(0, 8)}]`).join(' / ');
        addMetaLine('冲突窗口', cands || '多个活跃标签页', '#fcd34d');
      } else {
        addMetaLine('会话链接', apr.url || (apr.conversation_id ? `/app/${apr.conversation_id}` : '(首轮新对话待分配ID)'), '#93c5fd');
        if (apr.title) addMetaLine('窗口标题', apr.title);
      }
      addMetaLine('请求工具', apr.tool_name, '#ffffff');
      addMetaLine('所需权限', apr.capability_label || apr.capability, '#fde68a');
      if (apr.target_summary) addMetaLine('操作摘要', apr.target_summary, '#d4d4d8');

      let chkPersist = null;
      if (!apr.ambiguous) {
        const scopeRow = document.createElement('label');
        Object.assign(scopeRow.style, {
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          marginBottom: '10px',
          cursor: 'pointer',
          color: '#d4d4d8',
        });
        chkPersist = document.createElement('input');
        chkPersist.type = 'checkbox';
        chkPersist.checked = true;
        const scopeText = document.createElement('span');
        scopeText.textContent = '永久记住此会话链接的授权（不勾选则仅本次打开有效）';
        scopeRow.appendChild(chkPersist);
        scopeRow.appendChild(scopeText);
        card.appendChild(hdr);
        card.appendChild(meta);
        card.appendChild(scopeRow);
      } else {
        card.appendChild(hdr);
        card.appendChild(meta);
      }

      const btnGrid = document.createElement('div');
      Object.assign(btnGrid.style, { display: 'flex', flexWrap: 'wrap', gap: '6px' });

      const allBtns = [];
      const mkBtn = (text, bg, onClick) => {
        const b = document.createElement('button');
        b.textContent = text;
        Object.assign(b.style, {
          padding: '6px 10px',
          borderRadius: '6px',
          border: 'none',
          background: bg,
          color: '#ffffff',
          fontSize: '12px',
          cursor: 'pointer',
        });
        b.addEventListener('click', async () => {
          allBtns.forEach((x) => { x.disabled = true; x.style.opacity = '0.55'; });
          await onClick();
        });
        allBtns.push(b);
        btnGrid.appendChild(b);
      };

      const chosenScope = () => (chkPersist && !chkPersist.checked ? 'session' : 'persistent');

      mkBtn('仅允许本次', '#3f3f46', () => submitApprovalDecision(apr.approval_id, { decision: 'allow_once' }));
      if (!apr.ambiguous) {
        mkBtn(`增开「${apr.capability_label}」`, '#2563eb', () => submitApprovalDecision(apr.approval_id, {
          decision: 'allow_capability',
          capability: apr.capability,
          scope: chosenScope(),
        }));
        if (apr.capability !== 'exec') {
          mkBtn('设为工作区读写', '#059669', () => submitApprovalDecision(apr.approval_id, {
            decision: 'allow_profile',
            profile: 'workspace',
            scope: chosenScope(),
          }));
        }
        mkBtn('设为完全权限', '#7c3aed', () => submitApprovalDecision(apr.approval_id, {
          decision: 'allow_profile',
          profile: 'full',
          scope: chosenScope(),
        }));
      }
      mkBtn('拒绝', '#dc2626', () => submitApprovalDecision(apr.approval_id, { decision: 'deny' }));

      card.appendChild(btnGrid);
      wrap.appendChild(card);
    }

    for (const sug of readySuggestions) {
      const card = document.createElement('div');
      Object.assign(card.style, {
        background: '#18181b',
        color: '#f4f4f5',
        border: '1px solid #06b6d4',
        borderRadius: '12px',
        padding: '14px',
        boxShadow: '0 10px 30px rgba(0,0,0,0.55)',
        fontSize: '12px',
        lineHeight: '1.5',
      });

      const hdr = document.createElement('div');
      Object.assign(hdr.style, {
        fontWeight: '600',
        fontSize: '13px',
        color: '#22d3ee',
        marginBottom: '6px',
      });
      hdr.textContent = '🧹 工作区目录屏蔽建议 · 保存后永久写入 config.json';
      card.appendChild(hdr);

      if (sug.workspace_dir || sug.reason) {
        const sub = document.createElement('div');
        Object.assign(sub.style, {
          background: '#27272a',
          borderRadius: '8px',
          padding: '7px 9px',
          marginBottom: '8px',
          color: '#d4d4d8',
          fontSize: '11px',
          wordBreak: 'break-all',
        });
        const parts = [];
        if (sug.workspace_dir) parts.push(`工作区: ${sug.workspace_dir}`);
        if (sug.reason) parts.push(`原因: ${sug.reason}`);
        sub.textContent = parts.join('\n');
        sub.style.whiteSpace = 'pre-line';
        card.appendChild(sub);
      }

      const dirChecks = [];
      const dirList = document.createElement('div');
      Object.assign(dirList.style, {
        display: 'flex',
        flexDirection: 'column',
        gap: '5px',
        marginBottom: '10px',
        maxHeight: '140px',
        overflowY: 'auto',
      });
      for (const d of (sug.dirs || [])) {
        const lbl = document.createElement('label');
        Object.assign(lbl.style, {
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          cursor: 'pointer',
          background: '#111214',
          padding: '5px 8px',
          borderRadius: '6px',
        });
        const chk = document.createElement('input');
        chk.type = 'checkbox';
        chk.checked = true;
        const txt = document.createElement('span');
        txt.textContent = d;
        txt.style.color = '#67e8f9';
        txt.style.fontFamily = 'monospace';
        lbl.appendChild(chk);
        lbl.appendChild(txt);
        dirList.appendChild(lbl);
        dirChecks.push({ dir: d, chk });
      }
      card.appendChild(dirList);

      const btnRow = document.createElement('div');
      Object.assign(btnRow.style, { display: 'flex', gap: '6px', flexWrap: 'wrap' });

      const btnApprove = document.createElement('button');
      btnApprove.textContent = '💾 保存选中项并永久生效';
      Object.assign(btnApprove.style, {
        padding: '6px 10px',
        borderRadius: '6px',
        border: 'none',
        background: '#0891b2',
        color: '#ffffff',
        fontSize: '12px',
        cursor: 'pointer',
      });

      const btnDismiss = document.createElement('button');
      btnDismiss.textContent = '忽略建议';
      Object.assign(btnDismiss.style, {
        padding: '6px 10px',
        borderRadius: '6px',
        border: '1px solid #52525b',
        background: 'transparent',
        color: '#e4e4e7',
        fontSize: '12px',
        cursor: 'pointer',
      });

      btnApprove.addEventListener('click', async () => {
        btnApprove.disabled = true;
        btnDismiss.disabled = true;
        const picked = dirChecks.filter((x) => x.chk.checked).map((x) => x.dir);
        if (picked.length === 0) {
          await submitIgnoreDecision(sug.suggestion_id, 'dismiss', []);
          return;
        }
        await submitIgnoreDecision(sug.suggestion_id, 'approve', picked);
      });
      btnDismiss.addEventListener('click', async () => {
        btnApprove.disabled = true;
        btnDismiss.disabled = true;
        await submitIgnoreDecision(sug.suggestion_id, 'dismiss', []);
      });

      btnRow.appendChild(btnApprove);
      btnRow.appendChild(btnDismiss);
      card.appendChild(btnRow);
      wrap.appendChild(card);
    }

    approvalRoot.appendChild(wrap);

    if (approvalTickTimer) clearInterval(approvalTickTimer);
    if (countdownLabels.length > 0) {
      approvalTickTimer = setInterval(() => {
        for (const item of countdownLabels) {
          const rem = Math.max(0, Math.ceil((approvalDeadlines.get(item.id) - Date.now()) / 1000));
          item.el.textContent = `${rem}s`;
        }
      }, 500);
    } else {
      approvalTickTimer = null;
    }
  }

  function ensurePill() {
    if (pillEl || !document.body) return;
    pillEl = document.createElement('div');
    Object.assign(pillEl.style, {
      position: 'fixed',
      bottom: '10px',
      right: '16px',
      zIndex: '99999',
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      padding: '5px 10px',
      borderRadius: '999px',
      background: 'rgba(24, 24, 27, 0.86)',
      color: '#e4e4e7',
      border: '1px solid rgba(255,255,255,0.14)',
      fontSize: '12px',
      fontFamily: 'system-ui, sans-serif',
      cursor: 'pointer',
      boxShadow: '0 2px 10px rgba(0,0,0,0.35)',
      userSelect: 'none',
    });

    dotEl = document.createElement('span');
    Object.assign(dotEl.style, {
      width: '8px',
      height: '8px',
      borderRadius: '50%',
      display: 'inline-block',
      background: '#9ca3af',
    });

    labelEl = document.createElement('span');
    labelEl.textContent = 'MCP';

    pillEl.appendChild(dotEl);
    pillEl.appendChild(labelEl);
    pillEl.addEventListener('click', openConfigModal);
    document.body.appendChild(pillEl);
    updatePill();
  }

  function openConfigModal() {
    const existing = document.getElementById('pc-work-mcp-modal');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'pc-work-mcp-modal';
    Object.assign(overlay.style, {
      position: 'fixed',
      inset: '0',
      zIndex: '100000',
      background: 'rgba(0,0,0,0.6)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
    });

    const card = document.createElement('div');
    Object.assign(card.style, {
      width: '560px',
      maxWidth: '94vw',
      maxHeight: '88vh',
      overflowY: 'auto',
      background: '#1e1f22',
      color: '#f4f4f5',
      border: '1px solid #3f3f46',
      borderRadius: '12px',
      padding: '18px',
      fontFamily: 'system-ui, sans-serif',
      boxShadow: '0 12px 32px rgba(0,0,0,0.55)',
    });

    const cid = getConversationId();
    const h3 = document.createElement('h3');
    h3.textContent = 'pc-work-mcp 本地桥 · 会话权限与连接设置';
    Object.assign(h3.style, { margin: '0 0 8px 0', fontSize: '16px' });

    const info = document.createElement('div');
    info.textContent = `当前会话: ${cid ? `https://gemini.google.com/app/${cid}` : '(首轮暂无链接 ID，授权后会在首轮结束自动转绑)'} | Tab: ${TAB_ID}`;
    Object.assign(info.style, { fontSize: '12px', color: '#93c5fd', marginBottom: '12px', wordBreak: 'break-all' });

    const makeSectionTitle = (title) => {
      const s = document.createElement('div');
      s.textContent = title;
      Object.assign(s.style, {
        fontSize: '13px',
        fontWeight: '600',
        color: '#e4e4e7',
        margin: '12px 0 6px 0',
        borderTop: '1px solid #2e2e34',
        paddingTop: '10px',
      });
      return s;
    };

    // --- Section 1: 当前会话权限管理 ---
    const permBox = document.createElement('div');
    const permStatusMsg = document.createElement('div');
    Object.assign(permStatusMsg.style, { fontSize: '12px', color: '#a1a1aa', marginBottom: '8px' });

    const presetRow = document.createElement('div');
    Object.assign(presetRow.style, { display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '10px' });

    const capBoxWrap = document.createElement('div');
    Object.assign(capBoxWrap.style, {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
      gap: '6px',
      background: '#111214',
      padding: '10px',
      borderRadius: '8px',
      marginBottom: '10px',
    });

    const capChecks = new Map();
    let selectedProfile = (currentPolicy && currentPolicy.profile) || 'ask';
    const curCaps = new Set((currentPolicy && currentPolicy.capabilities) || []);

    const presetButtons = new Map();
    const refreshPresetHighlight = () => {
      for (const [pid, btn] of presetButtons.entries()) {
        const active = pid === selectedProfile;
        btn.style.background = active ? '#2563eb' : '#27272a';
        btn.style.borderColor = active ? '#60a5fa' : '#3f3f46';
      }
    };

    for (const preset of PROFILE_PRESETS) {
      const b = document.createElement('button');
      b.textContent = preset.label;
      Object.assign(b.style, {
        padding: '5px 10px',
        borderRadius: '6px',
        border: '1px solid #3f3f46',
        background: '#27272a',
        color: '#f4f4f5',
        fontSize: '12px',
        cursor: 'pointer',
      });
      b.addEventListener('click', () => {
        selectedProfile = preset.id;
        const pset = new Set(preset.caps);
        for (const [cidKey, chk] of capChecks.entries()) {
          chk.checked = pset.has(cidKey);
        }
        refreshPresetHighlight();
      });
      presetButtons.set(preset.id, b);
      presetRow.appendChild(b);
    }

    for (const opt of CAP_OPTIONS) {
      const lbl = document.createElement('label');
      Object.assign(lbl.style, { display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', cursor: 'pointer' });
      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.checked = curCaps.has(opt.id);
      chk.addEventListener('change', () => {
        selectedProfile = 'custom';
        refreshPresetHighlight();
      });
      const txt = document.createElement('span');
      txt.textContent = opt.label;
      lbl.appendChild(chk);
      lbl.appendChild(txt);
      capChecks.set(opt.id, chk);
      capBoxWrap.appendChild(lbl);
    }
    refreshPresetHighlight();

    const scopeRow = document.createElement('div');
    Object.assign(scopeRow.style, { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', marginBottom: '8px' });
    const scopeLbl = document.createElement('label');
    Object.assign(scopeLbl.style, { display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: '#d4d4d8', cursor: 'pointer' });
    const chkPersist = document.createElement('input');
    chkPersist.type = 'checkbox';
    chkPersist.checked = !(currentPolicy && currentPolicy.scope === 'session');
    const scopeTxt = document.createElement('span');
    scopeTxt.textContent = '永久记住当前会话链接权限（不勾选则仅本次打开生效）';
    scopeLbl.appendChild(chkPersist);
    scopeLbl.appendChild(scopeTxt);

    const btnApplyPerm = document.createElement('button');
    btnApplyPerm.textContent = '保存当前会话权限';
    Object.assign(btnApplyPerm.style, {
      padding: '6px 12px',
      borderRadius: '6px',
      border: 'none',
      background: '#059669',
      color: '#ffffff',
      fontSize: '12px',
      cursor: 'pointer',
      whiteSpace: 'nowrap',
    });
    scopeRow.appendChild(scopeLbl);
    scopeRow.appendChild(btnApplyPerm);

    permBox.appendChild(permStatusMsg);
    permBox.appendChild(presetRow);
    permBox.appendChild(capBoxWrap);
    permBox.appendChild(scopeRow);

    // --- Section 2: 已保存会话列表 ---
    const savedListEl = document.createElement('div');
    Object.assign(savedListEl.style, {
      maxHeight: '160px',
      overflowY: 'auto',
      display: 'flex',
      flexDirection: 'column',
      gap: '6px',
      marginBottom: '8px',
    });

    // --- Section 2.5: 当前窗口工作区目录（选择保存与会话绑定） ---
    const wsBox = document.createElement('div');
    Object.assign(wsBox.style, {
      background: '#111214',
      borderRadius: '8px',
      padding: '10px',
      marginBottom: '8px',
      fontSize: '12px',
    });

    const wsCurrentRow = document.createElement('div');
    Object.assign(wsCurrentRow.style, {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      gap: '8px',
      marginBottom: '8px',
    });
    const wsCurrentMsg = document.createElement('div');
    wsCurrentMsg.textContent = '正在读取工作区配置...';
    Object.assign(wsCurrentMsg.style, { color: '#a1a1aa', lineHeight: '1.5', wordBreak: 'break-all', flex: '1' });

    const btnResetDefaultWs = document.createElement('button');
    btnResetDefaultWs.textContent = '恢复默认工作区';
    Object.assign(btnResetDefaultWs.style, {
      padding: '4px 9px',
      borderRadius: '5px',
      border: '1px solid #52525b',
      background: 'transparent',
      color: '#e4e4e7',
      fontSize: '11px',
      cursor: 'pointer',
      whiteSpace: 'nowrap',
      display: 'none',
    });
    wsCurrentRow.appendChild(wsCurrentMsg);
    wsCurrentRow.appendChild(btnResetDefaultWs);

    const savedWsListEl = document.createElement('div');
    Object.assign(savedWsListEl.style, {
      maxHeight: '130px',
      overflowY: 'auto',
      display: 'flex',
      flexDirection: 'column',
      gap: '5px',
      marginBottom: '8px',
    });

    const inpWsDir = document.createElement('input');
    inpWsDir.type = 'text';
    inpWsDir.placeholder = '输入或粘贴项目文件夹路径（支持 D:\\project 或 /d/project）';
    Object.assign(inpWsDir.style, {
      width: '100%',
      boxSizing: 'border-box',
      padding: '7px 8px',
      borderRadius: '6px',
      border: '1px solid #3f3f46',
      background: '#18181b',
      color: '#fafafa',
      fontSize: '12px',
      marginBottom: '8px',
    });

    const wsBtnRow = document.createElement('div');
    Object.assign(wsBtnRow.style, { display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '8px' });

    const mkSmallBtn = (label, bg, border = 'none', color = '#ffffff') => {
      const b = document.createElement('button');
      b.textContent = label;
      Object.assign(b.style, {
        padding: '5px 10px',
        borderRadius: '6px',
        border,
        background: bg,
        color,
        fontSize: '12px',
        cursor: 'pointer',
      });
      return b;
    };

    const btnPickFolder = mkSmallBtn('📂 本机选文件夹并绑定', '#059669');
    const btnAddSavedWs = mkSmallBtn('仅保存目录', '#27272a', '1px solid #52525b', '#e4e4e7');
    const btnBindWs = mkSmallBtn('保存并绑定当前会话', '#2563eb');
    wsBtnRow.appendChild(btnPickFolder);
    wsBtnRow.appendChild(btnBindWs);
    wsBtnRow.appendChild(btnAddSavedWs);

    const rulesDivider = document.createElement('div');
    Object.assign(rulesDivider.style, {
      borderTop: '1px solid #27272a',
      paddingTop: '8px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'flex-start',
      gap: '8px',
    });
    const rulesInfoMsg = document.createElement('div');
    rulesInfoMsg.textContent = '正在读取工作区规则状态...';
    Object.assign(rulesInfoMsg.style, { color: '#a1a1aa', lineHeight: '1.5', wordBreak: 'break-all', flex: '1', fontSize: '11px' });

    const btnForceReinject = mkSmallBtn('下轮强制重注规则', 'transparent', '1px solid #52525b', '#e4e4e7');
    btnForceReinject.style.fontSize = '11px';
    btnForceReinject.style.padding = '4px 8px';
    btnForceReinject.style.whiteSpace = 'nowrap';
    rulesDivider.appendChild(rulesInfoMsg);
    rulesDivider.appendChild(btnForceReinject);

    wsBox.appendChild(wsCurrentRow);
    wsBox.appendChild(savedWsListEl);
    wsBox.appendChild(inpWsDir);
    wsBox.appendChild(wsBtnRow);
    wsBox.appendChild(rulesDivider);

    const planDivider = document.createElement('div');
    Object.assign(planDivider.style, {
      borderTop: '1px solid #27272a',
      paddingTop: '8px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'flex-start',
      gap: '8px',
    });
    const planInfoMsg = document.createElement('div');
    planInfoMsg.textContent = '任务计划: 当前会话暂无进行中计划';
    Object.assign(planInfoMsg.style, { color: '#71717a', lineHeight: '1.5', wordBreak: 'break-word', flex: '1', fontSize: '11px' });

    const btnStopPlan = mkSmallBtn('⏸ 停止自动续跑', 'transparent', '1px solid #dc2626', '#fca5a5');
    btnStopPlan.style.fontSize = '11px';
    btnStopPlan.style.padding = '4px 8px';
    btnStopPlan.style.whiteSpace = 'nowrap';
    btnStopPlan.style.display = 'none';
    planDivider.appendChild(planInfoMsg);
    planDivider.appendChild(btnStopPlan);
    wsBox.appendChild(planDivider);

    // Gemini 官方配置入口：全局提示词、关联应用(MCP)与技能均在官方页面维护，避免脆性前端注入
    const geminiLinksDivider = document.createElement('div');
    Object.assign(geminiLinksDivider.style, {
      borderTop: '1px solid #27272a',
      paddingTop: '8px',
      display: 'flex',
      flexWrap: 'wrap',
      alignItems: 'center',
      gap: '6px',
    });
    const geminiLinksLbl = document.createElement('span');
    geminiLinksLbl.textContent = 'Gemini 官方设置:';
    Object.assign(geminiLinksLbl.style, { color: '#a1a1aa', fontSize: '11px', marginRight: '2px' });
    geminiLinksDivider.appendChild(geminiLinksLbl);

    const officialLinks = [
      ['全局指令 (saved-info)', 'https://gemini.google.com/saved-info'],
      ['关联应用 / MCP (connectors)', 'https://gemini.google.com/customize/connectors'],
      ['技能 (skills)', 'https://gemini.google.com/customize/skills'],
    ];
    for (const [label, href] of officialLinks) {
      const a = document.createElement('a');
      a.textContent = label;
      a.href = href;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      Object.assign(a.style, {
        color: '#93c5fd',
        fontSize: '11px',
        textDecoration: 'none',
        padding: '2px 7px',
        borderRadius: '6px',
        border: '1px solid #3f3f46',
        background: '#18181b',
      });
      geminiLinksDivider.appendChild(a);
    }
    wsBox.appendChild(geminiLinksDivider);

    // --- Section 2.6: 全局白名单目录（跨所有非禁止会话免授权自由读写） ---
    const wlBox = document.createElement('div');
    Object.assign(wlBox.style, {
      background: '#111214',
      borderRadius: '8px',
      padding: '10px',
      marginBottom: '8px',
      fontSize: '12px',
    });

    const wlInfoMsg = document.createElement('div');
    wlInfoMsg.textContent =
      '填入此处的文件夹（如日记本、知识库）在所有未设为「禁止」的会话中均可直接自由读取/写入，无需每次开新对话重复授权，也不会触发工作区外弹窗（即时热生效）。';
    Object.assign(wlInfoMsg.style, { color: '#a1a1aa', lineHeight: '1.5', fontSize: '11px', marginBottom: '8px' });

    const wlListEl = document.createElement('div');
    Object.assign(wlListEl.style, {
      maxHeight: '140px',
      overflowY: 'auto',
      display: 'flex',
      flexDirection: 'column',
      gap: '5px',
      marginBottom: '8px',
    });

    const inpWlDir = document.createElement('input');
    inpWlDir.type = 'text';
    inpWlDir.placeholder = '输入或粘贴全局白名单文件夹路径（如 D:\\MyDiary，支持带引号复制路径）';
    Object.assign(inpWlDir.style, {
      width: '100%',
      boxSizing: 'border-box',
      padding: '7px 8px',
      borderRadius: '6px',
      border: '1px solid #3f3f46',
      background: '#18181b',
      color: '#fafafa',
      fontSize: '12px',
      marginBottom: '6px',
    });

    const wlOptsRow = document.createElement('div');
    Object.assign(wlOptsRow.style, {
      display: 'flex',
      flexWrap: 'wrap',
      gap: '12px',
      marginBottom: '8px',
      fontSize: '11px',
      color: '#d4d4d8',
    });

    const lblWlReadonly = document.createElement('label');
    Object.assign(lblWlReadonly.style, { display: 'flex', alignItems: 'center', gap: '5px', cursor: 'pointer' });
    const chkWlReadonly = document.createElement('input');
    chkWlReadonly.type = 'checkbox';
    const txtWlReadonly = document.createElement('span');
    txtWlReadonly.textContent = '仅只读（允许自由读取，禁止写入）';
    lblWlReadonly.appendChild(chkWlReadonly);
    lblWlReadonly.appendChild(txtWlReadonly);

    const lblWlExec = document.createElement('label');
    Object.assign(lblWlExec.style, { display: 'flex', alignItems: 'center', gap: '5px', cursor: 'pointer' });
    const chkWlExec = document.createElement('input');
    chkWlExec.type = 'checkbox';
    const txtWlExec = document.createElement('span');
    txtWlExec.textContent = '允许以该目录为 cwd 免批执行脚本';
    lblWlExec.appendChild(chkWlExec);
    lblWlExec.appendChild(txtWlExec);

    chkWlReadonly.addEventListener('change', () => {
      if (chkWlReadonly.checked) {
        chkWlExec.checked = false;
        chkWlExec.disabled = true;
      } else {
        chkWlExec.disabled = false;
      }
    });
    wlOptsRow.appendChild(lblWlReadonly);
    wlOptsRow.appendChild(lblWlExec);

    const wlBtnRow = document.createElement('div');
    Object.assign(wlBtnRow.style, { display: 'flex', gap: '6px', flexWrap: 'wrap' });
    const btnPickWlFolder = mkSmallBtn('📂 本机选文件夹加入白名单', '#059669');
    const btnAddWl = mkSmallBtn('➕ 添加路径到白名单', '#2563eb');
    wlBtnRow.appendChild(btnPickWlFolder);
    wlBtnRow.appendChild(btnAddWl);

    wlBox.appendChild(wlInfoMsg);
    wlBox.appendChild(wlListEl);
    wlBox.appendChild(inpWlDir);
    wlBox.appendChild(wlOptsRow);
    wlBox.appendChild(wlBtnRow);

    // --- Section 2.7: 忽略检索目录（workspace.ignored_dirs，即时热生效） ---
    const ignBox = document.createElement('div');
    Object.assign(ignBox.style, {
      background: '#111214',
      borderRadius: '8px',
      padding: '10px',
      marginBottom: '8px',
      fontSize: '12px',
    });

    const ignInfoMsg = document.createElement('div');
    ignInfoMsg.textContent =
      '此处填入目录名或通配符（如 logs、outbox、pc-work-mcp-v*，也可粘贴完整路径自动提取目录名），' +
      'list_dir / find_files / grep_search 默认跳过这些目录并永久写入 config.json。';
    Object.assign(ignInfoMsg.style, { color: '#a1a1aa', lineHeight: '1.5', fontSize: '11px', marginBottom: '6px' });

    const ignDefaultMsg = document.createElement('div');
    ignDefaultMsg.textContent = '内置默认屏蔽: .git, node_modules, __pycache__, .venv, .brave-agent-profile 等';
    Object.assign(ignDefaultMsg.style, { color: '#71717a', lineHeight: '1.4', fontSize: '11px', marginBottom: '8px' });

    const ignListEl = document.createElement('div');
    Object.assign(ignListEl.style, {
      maxHeight: '130px',
      overflowY: 'auto',
      display: 'flex',
      flexDirection: 'column',
      gap: '5px',
      marginBottom: '8px',
    });

    const inpIgnDir = document.createElement('input');
    inpIgnDir.type = 'text';
    inpIgnDir.placeholder = '输入目录名、通配符（如 pc-work-mcp-v*）或粘贴路径（支持逗号分隔多项）';
    Object.assign(inpIgnDir.style, {
      width: '100%',
      boxSizing: 'border-box',
      padding: '7px 8px',
      borderRadius: '6px',
      border: '1px solid #3f3f46',
      background: '#18181b',
      color: '#fafafa',
      fontSize: '12px',
      marginBottom: '8px',
    });

    const ignBtnRow = document.createElement('div');
    Object.assign(ignBtnRow.style, { display: 'flex', gap: '6px', flexWrap: 'wrap' });
    const btnPickIgnFolder = mkSmallBtn('📂 选目录加入忽略', '#059669');
    const btnAddIgn = mkSmallBtn('➕ 添加忽略规则', '#0891b2');
    ignBtnRow.appendChild(btnPickIgnFolder);
    ignBtnRow.appendChild(btnAddIgn);

    ignBox.appendChild(ignInfoMsg);
    ignBox.appendChild(ignDefaultMsg);
    ignBox.appendChild(ignListEl);
    ignBox.appendChild(inpIgnDir);
    ignBox.appendChild(ignBtnRow);

    // 公网入口外网双栈 TCP 自检区（默认启动不卡死；配置好域名/反代后，在接入 Google MCP 前自己测通不通）
    const pubBox = document.createElement('div');
    Object.assign(pubBox.style, {
      border: '1px solid #3f3f46',
      borderRadius: '8px',
      padding: '10px',
      marginBottom: '12px',
      background: '#111214',
    });
    const pubTip = document.createElement('div');
    pubTip.textContent = '⚠️ 在设置 Google「关联应用 / MCP (connectors)」前，请先测试你的公网入口域名与端口是否真的能从外网连入本机（兼容国内纯 IPv6 宽带 / IPv4）。';
    Object.assign(pubTip.style, { fontSize: '11px', color: '#fde68a', marginBottom: '8px', lineHeight: '1.5' });

    const inpPubUrl = document.createElement('input');
    inpPubUrl.type = 'text';
    inpPubUrl.placeholder = '填写公网入口 URL（如 https://mcp.example.com:14769）';
    Object.assign(inpPubUrl.style, {
      width: '100%',
      boxSizing: 'border-box',
      padding: '7px 8px',
      borderRadius: '6px',
      border: '1px solid #3f3f46',
      background: '#18181b',
      color: '#fafafa',
      fontSize: '12px',
      marginBottom: '8px',
    });

    const pubBtnRow = document.createElement('div');
    Object.assign(pubBtnRow.style, { display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '8px' });
    const btnTestPub = mkSmallBtn('🌐 测试外网双栈 TCP 连通性', '#2563eb');
    const btnSaveAndTestPub = mkSmallBtn('💾 保存公网地址到 config 并测试', '#059669');
    pubBtnRow.appendChild(btnTestPub);
    pubBtnRow.appendChild(btnSaveAndTestPub);

    const pubStatusMsg = document.createElement('div');
    pubStatusMsg.textContent = '等待测试（未填写公网域名时仅本机/油猴可用，不影响本地服务启动）。';
    Object.assign(pubStatusMsg.style, {
      fontSize: '11px',
      color: '#a1a1aa',
      lineHeight: '1.5',
      whiteSpace: 'pre-wrap',
      wordBreak: 'break-word',
    });

    pubBox.appendChild(pubTip);
    pubBox.appendChild(inpPubUrl);
    pubBox.appendChild(pubBtnRow);
    pubBox.appendChild(pubStatusMsg);

    function renderPublicCheckResult(resp) {
      if (!resp || !resp.check) return;
      const chk = resp.check;
      const st = chk.status || 'unknown';
      const fam = chk.families || {};
      const v6 = (fam.ipv6 && fam.ipv6.state) || '-';
      const v4 = (fam.ipv4 && fam.ipv4.state) || '-';
      const target = (chk.host && chk.port) ? `${chk.host}:${chk.port}` : (resp.public_base_url || '(未填写)');
      const savedNote = resp.saved ? '（已写入 config.json 并热更新）\n' : '';
      if (st === 'reachable') {
        const fams = (chk.reachable_families || []).join('/') || 'TCP';
        pubStatusMsg.textContent = `${savedNote}✅ 外网 TCP 可达：${target}\n可达协议栈: ${fams}（IPv6=${v6} | IPv4=${v4}）。现在可以放心配置 Google MCP！`;
        pubStatusMsg.style.color = '#34d399';
      } else if (st === 'unreachable') {
        pubStatusMsg.textContent =
          `${savedNote}❌ 外网不可达：${target}（IPv6=${v6} | IPv4=${v4}）\n` +
          `此时连接 Google MCP 会失败。请依次排查：\n` +
          `1) 管理员运行 admin\\add-firewall.ps1 放行端口；\n` +
          `2) 路由器转发 / lucky 反代是否已启用且绑定当前最新 IPv6 前缀；\n` +
          `3) 公网域名与端口号是否拼写正确。`;
        pubStatusMsg.style.color = '#f87171';
      } else if (st === 'empty') {
        pubStatusMsg.textContent = `${savedNote}ℹ️ ${chk.reason || '未填写公网入口 URL。'}`;
        pubStatusMsg.style.color = '#a1a1aa';
      } else if (st === 'skipped') {
        pubStatusMsg.textContent = `${savedNote}⚠️ ${target} 为本机/内网地址，已跳过外网探测；接入 Google MCP 需填写公网域名。`;
        pubStatusMsg.style.color = '#fde68a';
      } else {
        pubStatusMsg.textContent = `${savedNote}⚠️ 外部在线探测服务暂不可用（IPv6=${v6} | IPv4=${v4}），请稍后重试或用手机流量验证。`;
        pubStatusMsg.style.color = '#fde68a';
      }
    }

    async function runPublicConnectivityCheck(saveFirst) {
      btnTestPub.disabled = true;
      btnSaveAndTestPub.disabled = true;
      pubStatusMsg.textContent = '正在调用外部双栈 TCP 探针检测（约 2~6 秒）...';
      pubStatusMsg.style.color = '#93c5fd';
      try {
        const res = await mcpJson('POST', '/bridge/check_public_url', {
          public_base_url: inpPubUrl.value.trim(),
          save: Boolean(saveFirst),
        });
        if (res && res.public_base_url && !inpPubUrl.value.trim()) {
          inpPubUrl.value = res.public_base_url;
        }
        renderPublicCheckResult(res);
      } catch (err) {
        pubStatusMsg.textContent = '公网连通性测试失败: ' + String(err && err.message ? err.message : err);
        pubStatusMsg.style.color = '#f87171';
      } finally {
        btnTestPub.disabled = false;
        btnSaveAndTestPub.disabled = false;
      }
    }

    btnTestPub.addEventListener('click', () => runPublicConnectivityCheck(false));
    btnSaveAndTestPub.addEventListener('click', () => runPublicConnectivityCheck(true));

    function renderTaskPlanInfo(plan) {
      currentTaskPlan = plan || null;
      if (!plan) {
        planInfoMsg.textContent = '任务计划: 当前会话暂无持久化计划（模型调 task_plan 后可显示进度与续跑次数）';
        planInfoMsg.style.color = '#71717a';
        btnStopPlan.style.display = 'none';
        return;
      }
      const st = plan.status || 'active';
      planInfoMsg.textContent =
        `计划 [${st}] (${plan.progress || '0/0'} · 续跑 ${plan.auto_turns_used || 0}/${plan.max_auto_turns || 5}): ` +
        `${plan.goal || ''}` +
        (plan.last_handoff ? `\n交接: ${plan.last_handoff}` : '');
      planInfoMsg.style.color = st === 'active' ? '#fde68a' : (st === 'completed' ? '#34d399' : '#a1a1aa');
      btnStopPlan.style.display = (st === 'active' || plan.pending_continue_task_id) ? 'inline-block' : 'none';
    }
    renderTaskPlanInfo(currentTaskPlan);

    btnStopPlan.addEventListener('click', async () => {
      activeContinueCancelled = true;
      await mcpJson('POST', '/bridge/task_plan', {
        action: 'stop',
        conversation_id: getConversationId(),
        tab_id: TAB_ID,
        reason: 'stopped_from_modal',
      }).catch(() => null);
      await sendHeartbeat(true);
      renderTaskPlanInfo(currentTaskPlan);
    });

    function renderRulesInfo(rs) {
      if (!rs) {
        rulesInfoMsg.textContent = '连接本地桥后可自动探测当前工作区的 AGENTS.md / GEMINI.md / .gemini/rules/*.md。';
        return;
      }
      currentRulesStatus = rs;
      const files = (rs.detected_files || []).map((f) => `${f.path}(${f.sha256_prefix})`).join(', ');
      const ses = rs.session || {};
      const remCalls = ses.remaining_calls_until_reinject;
      const callPart = remCalls !== null && remCalls !== undefined
        ? `${ses.calls_since_inject || 0}/${rs.reinject_every_calls || 20} 步`
        : `${ses.calls_since_inject || 0} 步`;
      const charPart = `${ses.output_chars_since_inject || 0}/${rs.reinject_every_output_chars || 96000} 字`;
      if (!files) {
        rulesInfoMsg.textContent = '规则注入: 当前工作区暂无 AGENTS.md / GEMINI.md / .gemini/rules/*.md（新建后下轮调工具自动注入）';
        rulesInfoMsg.style.color = '#71717a';
      } else {
        rulesInfoMsg.textContent = `规则文件: ${files} · 已注 ${ses.total_injections || 0} 次 · 重锚 ${callPart} / ${charPart}`;
        rulesInfoMsg.style.color = '#d4d4d8';
      }
    }
    if (currentRulesStatus) renderRulesInfo(currentRulesStatus);

    function renderWorkspacePanel(wsSnap) {
      if (!wsSnap) return;
      const liveTab = (wsSnap.live_tabs || []).find((t) => t.tab_id === TAB_ID);
      const eff = (liveTab && liveTab.workspace_binding) || currentWorkspace || {
        workspace_dir: wsSnap.server_default_workspace,
        is_custom: false,
        scope: 'default',
      };
      currentWorkspace = eff;
      const effDir = eff.workspace_dir || wsSnap.server_default_workspace || '';
      const isCustom = Boolean(eff.is_custom);
      wsCurrentMsg.textContent =
        `当前生效工作区: ${effDir}\n` +
        (isCustom
          ? `模式: 会话独立绑定（${eff.scope === 'session' ? '仅本次打开' : '永久记住'} · 与默认工作区逻辑完全一致）`
          : `模式: 跟随服务端默认工作区 (${wsSnap.server_default_workspace || ''})`);
      wsCurrentMsg.style.color = isCustom ? '#93c5fd' : '#d4d4d8';
      btnResetDefaultWs.style.display = isCustom ? 'inline-block' : 'none';

      while (savedWsListEl.firstChild) savedWsListEl.removeChild(savedWsListEl.firstChild);
      const savedList = wsSnap.saved_workspaces || [];
      if (savedList.length === 0) {
        const emptyWs = document.createElement('div');
        emptyWs.textContent = '暂无已保存的切换工作区目录，可点击下方按钮从本机挑选或粘贴路径保存。';
        emptyWs.style.color = '#71717a';
        emptyWs.style.fontSize = '11px';
        savedWsListEl.appendChild(emptyWs);
        return;
      }

      for (const item of savedList) {
        const row = document.createElement('div');
        const isActive = effDir && item.path && effDir.toLowerCase() === item.path.toLowerCase();
        Object.assign(row.style, {
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '6px',
          background: isActive ? '#172554' : '#18181b',
          border: isActive ? '1px solid #3b82f6' : '1px solid #27272a',
          padding: '6px 8px',
          borderRadius: '6px',
        });
        const left = document.createElement('div');
        left.style.overflow = 'hidden';
        left.style.flex = '1';
        const nameLine = document.createElement('div');
        nameLine.textContent =
          `📁 ${item.label || item.path}` +
          (isActive ? ' [当前绑定]' : '') +
          (item.exists === false ? ' [目录不存在]' : '');
        nameLine.style.color = isActive ? '#bfdbfe' : '#e4e4e7';
        nameLine.style.fontWeight = isActive ? '600' : '400';
        const pathLine = document.createElement('div');
        pathLine.textContent = item.path;
        pathLine.style.color = '#a1a1aa';
        pathLine.style.fontSize = '11px';
        pathLine.style.whiteSpace = 'nowrap';
        pathLine.style.overflow = 'hidden';
        pathLine.style.textOverflow = 'ellipsis';
        left.appendChild(nameLine);
        left.appendChild(pathLine);

        const acts = document.createElement('div');
        acts.style.display = 'flex';
        acts.style.gap = '4px';
        acts.style.flexShrink = '0';

        if (!isActive) {
          const btnUse = mkSmallBtn('切换', '#2563eb');
          btnUse.style.padding = '3px 8px';
          btnUse.style.fontSize = '11px';
          btnUse.addEventListener('click', async () => {
            try {
              await mcpJson('POST', '/bridge/workspaces', {
                action: 'bind',
                conversation_id: getConversationId(),
                tab_id: TAB_ID,
                workspace_dir: item.path,
                scope: chkPersist.checked ? 'persistent' : 'session',
                url: location.href,
                title: document.title,
                save_to_list: false,
              });
              await sendHeartbeat(true);
              await refreshPermissionsPanel();
            } catch (err) {
              wsCurrentMsg.textContent = '切换工作区失败: ' + String(err && err.message ? err.message : err);
              wsCurrentMsg.style.color = '#f87171';
            }
          });
          acts.appendChild(btnUse);
        }

        const btnRem = mkSmallBtn('移除', 'transparent', '1px solid #52525b', '#fca5a5');
        btnRem.style.padding = '3px 8px';
        btnRem.style.fontSize = '11px';
        btnRem.addEventListener('click', async () => {
          await mcpJson('POST', '/bridge/workspaces', {
            action: 'remove_saved',
            workspace_dir: item.path,
          });
          await refreshPermissionsPanel();
        });
        acts.appendChild(btnRem);

        row.appendChild(left);
        row.appendChild(acts);
        savedWsListEl.appendChild(row);
      }
    }

    function renderWhitelistPanel(wlSnap) {
      if (!wlSnap) return;
      while (wlListEl.firstChild) wlListEl.removeChild(wlListEl.firstChild);
      const entries = wlSnap.entries || [];
      if (entries.length === 0) {
        const emptyWl = document.createElement('div');
        emptyWl.textContent = '暂无全局白名单目录（可选择或粘贴本机日记本/笔记库路径，跨所有会话免弹窗自由读写）。';
        emptyWl.style.color = '#71717a';
        emptyWl.style.fontSize = '11px';
        wlListEl.appendChild(emptyWl);
        return;
      }

      for (const item of entries) {
        const isRo = item.mode === 'readonly';
        const allowExec = !isRo && Boolean(item.allow_exec);
        const row = document.createElement('div');
        Object.assign(row.style, {
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '6px',
          background: '#18181b',
          border: '1px solid #27272a',
          padding: '6px 8px',
          borderRadius: '6px',
        });

        const left = document.createElement('div');
        left.style.overflow = 'hidden';
        left.style.flex = '1';
        const nameLine = document.createElement('div');
        nameLine.textContent =
          `🌐 ${item.label || item.path}` +
          (isRo ? ' [仅只读]' : ' [自由读写]') +
          (allowExec ? ' [命令免批]' : '') +
          (item.exists === false ? ' [目录不存在]' : '');
        nameLine.style.color = item.exists === false ? '#fca5a5' : (isRo ? '#93c5fd' : '#86efac');
        nameLine.style.fontWeight = '600';
        const pathLine = document.createElement('div');
        pathLine.textContent = item.path;
        pathLine.style.color = '#a1a1aa';
        pathLine.style.fontSize = '11px';
        pathLine.style.whiteSpace = 'nowrap';
        pathLine.style.overflow = 'hidden';
        pathLine.style.textOverflow = 'ellipsis';
        left.appendChild(nameLine);
        left.appendChild(pathLine);

        const acts = document.createElement('div');
        acts.style.display = 'flex';
        acts.style.gap = '4px';
        acts.style.flexShrink = '0';

        const btnMode = mkSmallBtn(isRo ? '切读写' : '切只读', 'transparent', '1px solid #52525b', '#e4e4e7');
        btnMode.style.padding = '3px 7px';
        btnMode.style.fontSize = '11px';
        btnMode.addEventListener('click', async () => {
          try {
            const res = await mcpJson('POST', '/bridge/whitelist', {
              action: 'update',
              path: item.path,
              mode: isRo ? 'readwrite' : 'readonly',
            });
            renderWhitelistPanel(res);
          } catch (err) {
            wlInfoMsg.textContent = '切换模式失败: ' + String(err && err.message ? err.message : err);
            wlInfoMsg.style.color = '#f87171';
          }
        });
        acts.appendChild(btnMode);

        if (!isRo) {
          const btnExec = mkSmallBtn(
            allowExec ? '命令已免批' : '命令免批',
            allowExec ? '#78350f' : 'transparent',
            allowExec ? '1px solid #f59e0b' : '1px solid #52525b',
            allowExec ? '#fde68a' : '#d4d4d8',
          );
          btnExec.style.padding = '3px 7px';
          btnExec.style.fontSize = '11px';
          btnExec.title = '允许 cwd 设为该白名单目录的脚本在「按需询问」下免弹窗执行';
          btnExec.addEventListener('click', async () => {
            try {
              const res = await mcpJson('POST', '/bridge/whitelist', {
                action: 'update',
                path: item.path,
                allow_exec: !allowExec,
              });
              renderWhitelistPanel(res);
            } catch (err) {
              wlInfoMsg.textContent = '更新命令权限失败: ' + String(err && err.message ? err.message : err);
              wlInfoMsg.style.color = '#f87171';
            }
          });
          acts.appendChild(btnExec);
        }

        const btnRem = mkSmallBtn('移除', 'transparent', '1px solid #52525b', '#fca5a5');
        btnRem.style.padding = '3px 7px';
        btnRem.style.fontSize = '11px';
        btnRem.addEventListener('click', async () => {
          try {
            const res = await mcpJson('POST', '/bridge/whitelist', {
              action: 'remove',
              path: item.path,
            });
            renderWhitelistPanel(res);
          } catch (err) {
            wlInfoMsg.textContent = '移除失败: ' + String(err && err.message ? err.message : err);
            wlInfoMsg.style.color = '#f87171';
          }
        });
        acts.appendChild(btnRem);

        row.appendChild(left);
        row.appendChild(acts);
        wlListEl.appendChild(row);
      }
    }

    function renderIgnoredDirsPanel(ignSnap) {
      if (!ignSnap) return;
      if (Array.isArray(ignSnap.default_ignored) && ignSnap.default_ignored.length > 0) {
        ignDefaultMsg.textContent = `内置默认屏蔽 (${ignSnap.default_ignored.length}): ${ignSnap.default_ignored.join(', ')}`;
      }
      while (ignListEl.firstChild) ignListEl.removeChild(ignListEl.firstChild);
      const dirs = ignSnap.ignored_dirs || [];
      if (dirs.length === 0) {
        const emptyIgn = document.createElement('div');
        emptyIgn.textContent = '暂无自定义忽略目录（可在下方添加，或在模型发现根目录杂乱后通过弹窗一键保存）。';
        emptyIgn.style.color = '#71717a';
        emptyIgn.style.fontSize = '11px';
        ignListEl.appendChild(emptyIgn);
        return;
      }
      for (const dirName of dirs) {
        const row = document.createElement('div');
        Object.assign(row.style, {
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '8px',
          background: '#18181b',
          border: '1px solid #27272a',
          padding: '5px 8px',
          borderRadius: '6px',
        });
        const lbl = document.createElement('span');
        lbl.textContent = `🚫 ${dirName}`;
        lbl.style.color = '#67e8f9';
        lbl.style.fontFamily = 'monospace';
        lbl.style.fontSize = '12px';
        const btnRem = mkSmallBtn('移除', 'transparent', '1px solid #52525b', '#fca5a5');
        btnRem.style.padding = '2px 8px';
        btnRem.style.fontSize = '11px';
        btnRem.addEventListener('click', async () => {
          try {
            const res = await mcpJson('POST', '/bridge/ignored_dirs', {
              action: 'remove',
              dir: dirName,
            });
            renderIgnoredDirsPanel(res);
          } catch (err) {
            ignInfoMsg.textContent = '移除忽略目录失败: ' + String(err && err.message ? err.message : err);
            ignInfoMsg.style.color = '#f87171';
          }
        });
        row.appendChild(lbl);
        row.appendChild(btnRem);
        ignListEl.appendChild(row);
      }
    }
    refreshOpenModalIgnoredFn = renderIgnoredDirsPanel;

    async function refreshPermissionsPanel() {
      if (!getToken()) {
        permStatusMsg.textContent = '请先在下方填写本机派发的 auth.token 后测试连接。';
        return;
      }
      try {
        const [snap, rulesSnap, wsSnap, wlSnap, ignSnap, planResp, pubResp] = await Promise.all([
          mcpJson('GET', '/bridge/permissions'),
          mcpJson('GET', '/bridge/rules').catch(() => null),
          mcpJson('GET', '/bridge/workspaces').catch(() => null),
          mcpJson('GET', '/bridge/whitelist').catch(() => null),
          mcpJson('GET', '/bridge/ignored_dirs').catch(() => null),
          mcpJson('POST', '/bridge/task_plan', {
            action: 'get',
            conversation_id: getConversationId(),
            tab_id: TAB_ID,
          }).catch(() => null),
          mcpJson('GET', '/bridge/public_url').catch(() => null),
        ]);
        if (pubResp && typeof pubResp.public_base_url === 'string' && !inpPubUrl.value.trim()) {
          inpPubUrl.value = pubResp.public_base_url;
        }
        if (planResp) {
          renderTaskPlanInfo(planResp.plan || null);
        }
        if (wsSnap) {
          renderWorkspacePanel(wsSnap);
        }
        if (wlSnap) {
          renderWhitelistPanel(wlSnap);
        }
        if (ignSnap) {
          renderIgnoredDirsPanel(ignSnap);
        }
        if (rulesSnap && rulesSnap.tab_rules && rulesSnap.tab_rules[TAB_ID]) {
          renderRulesInfo(rulesSnap.tab_rules[TAB_ID]);
        } else if (currentRulesStatus) {
          renderRulesInfo(currentRulesStatus);
        }
        const activePol = (snap.live_tabs || []).find((t) => t.tab_id === TAB_ID)?.policy || currentPolicy;
        if (activePol) {
          currentPolicy = activePol;
          selectedProfile = activePol.profile || 'ask';
          const cset = new Set(activePol.capabilities || []);
          for (const [k, chk] of capChecks.entries()) chk.checked = cset.has(k);
          chkPersist.checked = activePol.scope !== 'session';
          refreshPresetHighlight();
          permStatusMsg.textContent = `当前档位：${activePol.profile_label || activePol.profile}（由本地桥掌控，不由 Agent 或 Google 掌管）`;
        }

        while (savedListEl.firstChild) savedListEl.removeChild(savedListEl.firstChild);
        const allItems = [
          ...(snap.session_conversations || []),
          ...(snap.persistent_conversations || []),
        ];
        if (allItems.length === 0) {
          const empty = document.createElement('div');
          empty.textContent = '暂无已保存的独立会话授权记录（所有新会话均先按默认策略）。';
          empty.style.fontSize = '12px';
          empty.style.color = '#71717a';
          savedListEl.appendChild(empty);
        } else {
          for (const item of allItems) {
            const row = document.createElement('div');
            Object.assign(row.style, {
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: '8px',
              background: '#111214',
              padding: '7px 10px',
              borderRadius: '6px',
              fontSize: '12px',
            });
            const left = document.createElement('div');
            left.style.overflow = 'hidden';
            const titleLine = document.createElement('div');
            titleLine.textContent = `${item.title || item.conversation_id} [${(item.conversation_id || '').slice(0, 8)}]`;
            titleLine.style.color = '#e4e4e7';
            titleLine.style.whiteSpace = 'nowrap';
            titleLine.style.overflow = 'hidden';
            titleLine.style.textOverflow = 'ellipsis';
            const subLine = document.createElement('div');
            subLine.textContent = `${PROFILE_SHORT[item.profile] || item.profile} (${item.scope === 'session' ? '本次会话' : '永久'}) · ${(item.capabilities || []).join(', ') || '无'}`;
            subLine.style.color = '#a1a1aa';
            subLine.style.fontSize = '11px';
            left.appendChild(titleLine);
            left.appendChild(subLine);

            const delBtn = document.createElement('button');
            delBtn.textContent = '撤销';
            Object.assign(delBtn.style, {
              padding: '4px 8px',
              borderRadius: '5px',
              border: '1px solid #52525b',
              background: 'transparent',
              color: '#fca5a5',
              fontSize: '11px',
              cursor: 'pointer',
              flexShrink: '0',
            });
            delBtn.addEventListener('click', async () => {
              await mcpJson('POST', '/bridge/permissions', {
                action: 'delete',
                conversation_id: item.conversation_id,
              });
              await sendHeartbeat(true);
              await refreshPermissionsPanel();
            });
            row.appendChild(left);
            row.appendChild(delBtn);
            savedListEl.appendChild(row);
          }
        }
      } catch (err) {
        permStatusMsg.textContent = '读取会话权限列表失败: ' + String(err && err.message ? err.message : err);
      }
    }

    btnApplyPerm.addEventListener('click', async () => {
      const checkedCaps = [];
      for (const [k, chk] of capChecks.entries()) {
        if (chk.checked) checkedCaps.push(k);
      }
      const payload = {
        action: 'set',
        conversation_id: getConversationId(),
        tab_id: TAB_ID,
        url: location.href,
        title: document.title,
        scope: chkPersist.checked ? 'persistent' : 'session',
      };
      if (selectedProfile === 'ask' || selectedProfile === 'deny') {
        payload.profile = selectedProfile;
      } else if (selectedProfile !== 'custom') {
        payload.profile = selectedProfile;
      } else {
        payload.capabilities = checkedCaps;
      }
      try {
        await mcpJson('POST', '/bridge/permissions', payload);
        await sendHeartbeat(true);
        await refreshPermissionsPanel();
        permStatusMsg.style.color = '#34d399';
      } catch (err) {
        permStatusMsg.textContent = '保存失败: ' + String(err && err.message ? err.message : err);
        permStatusMsg.style.color = '#f87171';
      }
    });

    // --- Section 3: MCP 地址与本地 Token ---
    const makeField = (labelText, value, type = 'text', placeholder = '') => {
      const wrap = document.createElement('div');
      wrap.style.marginBottom = '10px';
      const lbl = document.createElement('label');
      lbl.textContent = labelText;
      Object.assign(lbl.style, { display: 'block', fontSize: '12px', marginBottom: '4px', color: '#d4d4d8' });
      const inp = document.createElement('input');
      inp.type = type;
      inp.value = value;
      inp.placeholder = placeholder;
      Object.assign(inp.style, {
        width: '100%',
        boxSizing: 'border-box',
        padding: '8px',
        borderRadius: '6px',
        border: '1px solid #52525b',
        background: '#111214',
        color: '#fafafa',
        fontSize: '13px',
      });
      wrap.appendChild(lbl);
      wrap.appendChild(inp);
      return { wrap, inp };
    };

    const fUrl = makeField('本地 MCP 地址', getBaseUrl(), 'text', 'http://127.0.0.1:15672');
    const fTok = makeField('本地派发的鉴权 Token', getToken(), 'password', 'pcmcp_...');

    const msg = document.createElement('div');
    Object.assign(msg.style, { fontSize: '12px', minHeight: '18px', marginBottom: '10px', color: '#a1a1aa' });
    if (lastErrorMsg) msg.textContent = '上次错误: ' + lastErrorMsg;

    const btnRow = document.createElement('div');
    Object.assign(btnRow.style, { display: 'flex', justifyContent: 'flex-end', gap: '8px' });

    const btnClose = document.createElement('button');
    btnClose.textContent = '关闭';
    Object.assign(btnClose.style, {
      padding: '7px 14px',
      borderRadius: '6px',
      border: '1px solid #52525b',
      background: 'transparent',
      color: '#e4e4e7',
      cursor: 'pointer',
    });
    btnClose.addEventListener('click', () => overlay.remove());

    const btnSave = document.createElement('button');
    btnSave.textContent = '保存连接设置并测试';
    Object.assign(btnSave.style, {
      padding: '7px 14px',
      borderRadius: '6px',
      border: 'none',
      background: '#2563eb',
      color: '#ffffff',
      cursor: 'pointer',
    });
    btnSave.addEventListener('click', async () => {
      GM_setValue(KEY_BASE_URL, fUrl.inp.value.trim().replace(/\/+$/, ''));
      GM_setValue(KEY_TOKEN, fTok.inp.value.trim());
      msg.textContent = '正在测试连接...';
      await sendHeartbeat(true);
      msg.textContent = bridgeConnected ? '连接成功！已同步会话与权限状态。' : `连接失败: ${lastErrorMsg}`;
      msg.style.color = bridgeConnected ? '#34d399' : '#f87171';
      if (bridgeConnected) await refreshPermissionsPanel();
    });

    btnRow.appendChild(btnClose);
    btnRow.appendChild(btnSave);

    btnPickFolder.addEventListener('click', async () => {
      btnPickFolder.disabled = true;
      btnPickFolder.textContent = '请在系统弹窗选择文件夹...';
      try {
        const res = await mcpJson('POST', '/bridge/workspaces', {
          action: 'pick_folder',
          conversation_id: getConversationId(),
          tab_id: TAB_ID,
          bind: true,
          scope: chkPersist.checked ? 'persistent' : 'session',
          url: location.href,
          title: document.title,
          initial_dir: (currentWorkspace && currentWorkspace.workspace_dir) || '',
        });
        if (res && !res.cancelled) {
          await sendHeartbeat(true);
          await refreshPermissionsPanel();
        }
      } catch (err) {
        wsCurrentMsg.textContent = '弹窗选目录失败: ' + String(err && err.message ? err.message : err);
        wsCurrentMsg.style.color = '#f87171';
      } finally {
        btnPickFolder.disabled = false;
        btnPickFolder.textContent = '📂 本机选文件夹并绑定';
      }
    });

    btnAddSavedWs.addEventListener('click', async () => {
      try {
        const dir = inpWsDir.value.trim();
        if (!dir) throw new Error('请输入要保存的文件夹路径');
        await mcpJson('POST', '/bridge/workspaces', {
          action: 'add_saved',
          workspace_dir: dir,
        });
        inpWsDir.value = '';
        await refreshPermissionsPanel();
      } catch (err) {
        wsCurrentMsg.textContent = '保存目录失败: ' + String(err && err.message ? err.message : err);
        wsCurrentMsg.style.color = '#f87171';
      }
    });

    btnBindWs.addEventListener('click', async () => {
      try {
        const dir = inpWsDir.value.trim();
        if (!dir) throw new Error('请输入要绑定到当前会话的文件夹路径');
        await mcpJson('POST', '/bridge/workspaces', {
          action: 'bind',
          conversation_id: getConversationId(),
          tab_id: TAB_ID,
          workspace_dir: dir,
          scope: chkPersist.checked ? 'persistent' : 'session',
          url: location.href,
          title: document.title,
          save_to_list: true,
        });
        inpWsDir.value = '';
        await sendHeartbeat(true);
        await refreshPermissionsPanel();
      } catch (err) {
        wsCurrentMsg.textContent = '绑定工作区失败: ' + String(err && err.message ? err.message : err);
        wsCurrentMsg.style.color = '#f87171';
      }
    });

    btnResetDefaultWs.addEventListener('click', async () => {
      try {
        await mcpJson('POST', '/bridge/workspaces', {
          action: 'unbind',
          conversation_id: getConversationId(),
          tab_id: TAB_ID,
        });
        await sendHeartbeat(true);
        await refreshPermissionsPanel();
      } catch (err) {
        wsCurrentMsg.textContent = '恢复默认工作区失败: ' + String(err && err.message ? err.message : err);
        wsCurrentMsg.style.color = '#f87171';
      }
    });

    btnForceReinject.addEventListener('click', async () => {
      try {
        await mcpJson('POST', '/bridge/rules', {
          action: 'reset_session',
          conversation_id: getConversationId(),
          tab_id: TAB_ID,
        });
        await sendHeartbeat(true);
        await refreshPermissionsPanel();
      } catch (err) {
        rulesInfoMsg.textContent = '重置重注状态失败: ' + String(err && err.message ? err.message : err);
        rulesInfoMsg.style.color = '#f87171';
      }
    });

    btnPickWlFolder.addEventListener('click', async () => {
      btnPickWlFolder.disabled = true;
      btnPickWlFolder.textContent = '请在系统弹窗选择文件夹...';
      try {
        const res = await mcpJson('POST', '/bridge/whitelist', {
          action: 'pick_folder',
          mode: chkWlReadonly.checked ? 'readonly' : 'readwrite',
          allow_exec: !chkWlReadonly.checked && chkWlExec.checked,
          initial_dir: (currentWorkspace && currentWorkspace.workspace_dir) || '',
        });
        if (res && !res.cancelled) {
          renderWhitelistPanel(res);
          wlInfoMsg.textContent = '✅ 已添加到全局白名单（即时对所有非禁止会话生效）。';
          wlInfoMsg.style.color = '#34d399';
        }
      } catch (err) {
        wlInfoMsg.textContent = '弹窗加入白名单失败: ' + String(err && err.message ? err.message : err);
        wlInfoMsg.style.color = '#f87171';
      } finally {
        btnPickWlFolder.disabled = false;
        btnPickWlFolder.textContent = '📂 本机选文件夹加入白名单';
      }
    });

    btnAddWl.addEventListener('click', async () => {
      try {
        const dir = inpWlDir.value.trim();
        if (!dir) throw new Error('请输入要加入全局白名单的文件夹路径');
        const res = await mcpJson('POST', '/bridge/whitelist', {
          action: 'add',
          path: dir,
          mode: chkWlReadonly.checked ? 'readonly' : 'readwrite',
          allow_exec: !chkWlReadonly.checked && chkWlExec.checked,
        });
        inpWlDir.value = '';
        renderWhitelistPanel(res);
        wlInfoMsg.textContent = '✅ 已添加到全局白名单（即时对所有非禁止会话生效）。';
        wlInfoMsg.style.color = '#34d399';
      } catch (err) {
        wlInfoMsg.textContent = '添加全局白名单失败: ' + String(err && err.message ? err.message : err);
        wlInfoMsg.style.color = '#f87171';
      }
    });

    btnPickIgnFolder.addEventListener('click', async () => {
      btnPickIgnFolder.disabled = true;
      btnPickIgnFolder.textContent = '请在系统弹窗选择文件夹...';
      try {
        const res = await mcpJson('POST', '/bridge/ignored_dirs', { action: 'pick_folder' });
        if (res && !res.cancelled) {
          renderIgnoredDirsPanel(res);
          ignInfoMsg.textContent = `✅ 已将 ${(res.added || []).join(', ')} 永久写入 config.json 的 ignored_dirs。`;
          ignInfoMsg.style.color = '#34d399';
        }
      } catch (err) {
        ignInfoMsg.textContent = '弹窗加入忽略目录失败: ' + String(err && err.message ? err.message : err);
        ignInfoMsg.style.color = '#f87171';
      } finally {
        btnPickIgnFolder.disabled = false;
        btnPickIgnFolder.textContent = '📂 选目录加入忽略';
      }
    });

    btnAddIgn.addEventListener('click', async () => {
      try {
        const raw = inpIgnDir.value.trim();
        if (!raw) throw new Error('请输入目录名、通配符或目录路径');
        const parts = raw.split(/[,\n，]+/).map((s) => s.trim()).filter(Boolean);
        const res = await mcpJson('POST', '/bridge/ignored_dirs', {
          action: 'add',
          dirs: parts,
        });
        inpIgnDir.value = '';
        renderIgnoredDirsPanel(res);
        ignInfoMsg.textContent = '✅ 已更新并永久保存 workspace.ignored_dirs（即时生效）。';
        ignInfoMsg.style.color = '#34d399';
      } catch (err) {
        ignInfoMsg.textContent = '添加忽略目录失败: ' + String(err && err.message ? err.message : err);
        ignInfoMsg.style.color = '#f87171';
      }
    });

    const closeModal = () => {
      refreshOpenModalIgnoredFn = null;
      overlay.remove();
    };
    btnClose.onclick = null;
    btnClose.addEventListener('click', closeModal);

    card.appendChild(h3);
    card.appendChild(info);
    card.appendChild(makeSectionTitle('当前窗口工作区目录（独立切换与规则同步）'));
    card.appendChild(wsBox);
    card.appendChild(makeSectionTitle('全局白名单目录（跨所有非禁止会话免授权自由读写）'));
    card.appendChild(wlBox);
    card.appendChild(makeSectionTitle('忽略检索目录（list_dir / find_files / grep_search 自动跳过）'));
    card.appendChild(ignBox);
    card.appendChild(makeSectionTitle('当前窗口权限档位（基于本会话链接）'));
    card.appendChild(permBox);
    card.appendChild(makeSectionTitle('已授权的会话链接清单'));
    card.appendChild(savedListEl);
    card.appendChild(makeSectionTitle('公网入口连通性自检（配置 Google MCP 前必测）'));
    card.appendChild(pubBox);
    card.appendChild(makeSectionTitle('本地桥接连接配置'));
    card.appendChild(fUrl.wrap);
    card.appendChild(fTok.wrap);
    card.appendChild(msg);
    card.appendChild(btnRow);
    overlay.appendChild(card);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeModal();
    });
    document.body.appendChild(overlay);
    refreshPermissionsPanel();
  }

  // -------------------------------------------------------------------------
  // 启动入口
  // -------------------------------------------------------------------------
  hookNetwork();
  ensurePill();
  watchNavigation();

  if (typeof GM_registerMenuCommand === 'function') {
    GM_registerMenuCommand('🔐 管理当前窗口权限与桥接设置', openConfigModal);
    GM_registerMenuCommand('🔄 立即同步当前会话 ID', () => sendHeartbeat(true));
  }

  sendHeartbeat(true);
  setInterval(() => sendHeartbeat(false), 2000);
  setInterval(pollTasksOnce, 900);
})();
