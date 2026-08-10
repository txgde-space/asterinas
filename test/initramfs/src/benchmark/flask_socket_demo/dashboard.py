# SPDX-License-Identifier: MPL-2.0

COMPETITION_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Asterinas 指标二分步验证</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #07111f;
      --panel: #0e1d31;
      --panel-2: #12243b;
      --line: #29415f;
      --text: #f3f7fc;
      --muted: #9eb0c8;
      --cyan: #38d8ff;
      --green: #5ce6a8;
      --red: #ff6b7d;
      --amber: #ffd166;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: radial-gradient(circle at 12% 0%, #102b49, transparent 36rem), var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    button { font: inherit; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 24px 0 60px; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-bottom: 18px; }
    .brand { display: flex; align-items: center; gap: 13px; }
    .mark { display: grid; width: 44px; height: 44px; place-items: center; border: 1px solid #2789ad; border-radius: 13px; color: var(--cyan); font-size: 21px; font-weight: 900; }
    .brand strong { display: block; font-size: 18px; }
    .brand span { display: block; margin-top: 3px; color: var(--muted); font-size: 12px; }
    .online { color: var(--green); font-size: 13px; font-weight: 900; }
    .online::before { content: ""; display: inline-block; width: 9px; height: 9px; margin-right: 9px; border-radius: 50%; background: currentColor; box-shadow: 0 0 15px currentColor; }
    .hero { padding: 30px; border: 1px solid var(--line); border-radius: 18px; background: rgba(14, 29, 49, .92); }
    .editor-source-hidden { display: none; }
    .eyebrow { margin: 0 0 18px; color: var(--cyan); font-size: 11px; font-weight: 900; letter-spacing: .18em; }
    h1 { margin: 0; font-size: clamp(30px, 5vw, 52px); line-height: 1.08; letter-spacing: -.035em; }
    .hero p:last-child { max-width: 850px; margin: 16px 0 0; color: var(--muted); line-height: 1.7; }
    .capture-grid { display: grid; grid-template-columns: 1fr 1fr 1.1fr; gap: 10px; }
    .capture-proof { min-width: 0; padding: 16px; border: 1px solid var(--line); border-radius: 12px; background: #0a1728; }
    .capture-proof span { display: block; color: var(--muted); font-size: 10px; font-weight: 800; letter-spacing: .08em; }
    .capture-proof strong { display: block; margin: 8px 0 6px; color: var(--text); font-size: 14px; }
    .capture-proof code { color: var(--cyan); font-size: 11px; overflow-wrap: anywhere; }
    .capture-proof p { margin: 6px 0 0; color: var(--muted); font-size: 11px; line-height: 1.55; }
    .capture-command { display: flex; align-items: center; gap: 12px; margin-top: 10px; padding: 11px 14px; border: 1px solid rgba(92, 230, 168, .35); border-radius: 10px; background: rgba(92, 230, 168, .06); }
    .capture-command span { flex: 0 0 auto; color: var(--green); font-size: 10px; font-weight: 900; }
    .capture-command code { min-width: 0; color: #b9f8d8; font-size: 10px; overflow-wrap: anywhere; }
    .runtime { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 14px 0 20px; }
    .metric { padding: 14px; border: 1px solid var(--line); border-radius: 12px; background: var(--panel); }
    .metric span { display: block; color: var(--muted); font-size: 10px; font-weight: 800; }
    .metric strong { display: block; margin-top: 7px; overflow-wrap: anywhere; font-size: 13px; }
    .guide { display: flex; align-items: center; justify-content: space-between; gap: 15px; margin: 22px 0 12px; }
    .guide h2 { margin: 0; font-size: 20px; }
    .guide p { margin: 5px 0 0; color: var(--muted); font-size: 12px; }
    .counter { padding: 8px 12px; border: 1px solid var(--line); border-radius: 999px; color: var(--cyan); font-size: 12px; font-weight: 900; }
    .steps { display: grid; gap: 12px; }
    .step { display: grid; grid-template-columns: 64px minmax(0, 1fr) 150px; gap: 16px; align-items: center; padding: 18px; border: 1px solid var(--line); border-radius: 15px; background: var(--panel); transition: border-color .2s, opacity .2s; }
    .step.ready { border-color: rgba(56, 216, 255, .32); }
    .step.running { border-color: var(--cyan); box-shadow: inset 3px 0 0 var(--cyan); }
    .step.pass { border-color: rgba(92, 230, 168, .5); box-shadow: inset 3px 0 0 var(--green); }
    .step.fail { border-color: rgba(255, 107, 125, .55); box-shadow: inset 3px 0 0 var(--red); }
    .number { display: grid; width: 46px; height: 46px; place-items: center; border: 1px solid var(--line); border-radius: 50%; color: var(--muted); font-weight: 900; }
    .step.ready .number, .step.running .number { border-color: var(--cyan); color: var(--cyan); }
    .step.pass .number { border-color: var(--green); color: var(--green); }
    .step.fail .number { border-color: var(--red); color: var(--red); }
    .step-title { display: flex; align-items: baseline; gap: 9px; }
    .step-title strong { font-size: 15px; }
    .kind { display: none; }
    .description { margin: 6px 0 0; color: var(--muted); font-size: 12px; line-height: 1.6; }
    .expect { margin-top: 8px; color: var(--amber); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 10px; }
    .run-step { min-height: 40px; border: 1px solid var(--cyan); border-radius: 9px; background: transparent; color: var(--cyan); cursor: pointer; font-weight: 900; }
    .run-step:hover:not(:disabled) { background: rgba(56, 216, 255, .1); }
    .run-step:disabled { border-color: var(--line); color: var(--muted); cursor: not-allowed; }
    .step.pass .run-step { border-color: var(--green); color: var(--green); }
    .step.fail .run-step { border-color: var(--red); color: var(--red); }
    .evidence { display: none; grid-column: 2 / -1; padding-top: 14px; border-top: 1px solid var(--line); }
    .step.pass .evidence, .step.fail .evidence { display: block; }
    .comparison { display: grid; grid-template-columns: 1fr 1fr; gap: 9px; }
    .proof { padding: 10px; border: 1px solid var(--line); border-radius: 9px; background: #0a1728; }
    .proof span { display: block; margin-bottom: 5px; color: var(--muted); font-size: 9px; font-weight: 900; }
    .proof code { color: var(--text); font-size: 10px; overflow-wrap: anywhere; }
    .terminal-label { display: flex; align-items: center; justify-content: space-between; margin: 11px 0 6px; color: var(--muted); font-size: 10px; }
    .terminal-label b { color: var(--green); }
    pre { margin: 0; padding: 12px; overflow: auto; border: 1px solid #1f3857; border-radius: 9px; background: #050d18; color: #b9f8d8; font-size: 10px; line-height: 1.6; white-space: pre-wrap; }
    .final { display: none; margin-top: 15px; padding: 22px; border: 1px solid rgba(92,230,168,.5); border-radius: 15px; background: rgba(92,230,168,.08); }
    .final.show { display: flex; align-items: center; justify-content: space-between; gap: 18px; }
    .final strong { color: var(--green); font-size: 20px; }
    .reset { min-height: 40px; padding: 0 16px; border: 1px solid var(--green); border-radius: 9px; background: transparent; color: var(--green); cursor: pointer; font-weight: 900; }
    @media (max-width: 760px) {
      .capture-grid { grid-template-columns: 1fr; }
      .runtime { grid-template-columns: 1fr 1fr; }
      .step { grid-template-columns: 48px 1fr; }
      .run-step { grid-column: 2; }
      .evidence { grid-column: 1 / -1; }
    }
    @media (max-width: 520px) {
      .shell { width: min(100% - 18px, 1180px); }
      .topbar, .guide, .final.show { align-items: flex-start; flex-direction: column; }
      .hero { padding: 22px; }
      .runtime, .comparison { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand"><div class="mark">A</div><div><strong>Asterinas网络接口语义差异修复</strong><span>指标二 · 分步测试验证</span></div></div>
      <div class="online">QEMU 客体服务在线</div>
    </header>

    <section class="hero">
      <p class="eyebrow">抓包说明</p>
      <h1 class="editor-source-hidden">网页走一步，终端打一条证据</h1>
      <p class="editor-source-hidden">不再一键批量执行，也不限制操作顺序。任意点击一个兼容点，页面只运行该项；双网卡路径同时可由宿主机 QEMU PCAP 独立观察。</p>
      <div class="capture-grid">
        <div class="capture-proof">
          <span data-editor-id="capture-net0-label">QEMU NET0 原始帧</span>
          <strong data-editor-id="capture-net0-file">flask-net0.pcap</strong>
          <code data-editor-id="capture-net0-route">18080 → 10.0.2.15:8080</code>
        </div>
        <div class="capture-proof">
          <span data-editor-id="capture-net1-label">QEMU NET1 原始帧</span>
          <strong data-editor-id="capture-net1-file">flask-net1.pcap</strong>
          <code data-editor-id="capture-net1-route">18081 → 10.0.3.15:8080</code>
        </div>
        <div class="capture-proof">
          <span data-editor-id="capture-rule-label">独立判据</span>
          <strong data-editor-id="capture-rule-title">随机 Token + 目标地址 + TCP 载荷</strong>
          <p data-editor-id="capture-rule-copy">由宿主机直接解析 QEMU 网卡流量，不采用 Flask 自报日志作为路径通过条件。</p>
        </div>
      </div>
      <div class="capture-command">
        <span data-editor-id="capture-command-label">宿主机实时观察</span>
        <code data-editor-id="capture-command">python3 scripts/watch-flask-pcap-evidence.py target/flask-net0.pcap target/flask-net1.pcap</code>
      </div>
    </section>

    <section class="runtime">
      <div class="metric"><span>FLASK 进程</span><strong id="pid">读取中</strong></div>
      <div class="metric"><span>唯一通配 LISTENER</span><strong id="listener">读取中</strong></div>
      <div class="metric"><span>当前网页入口</span><strong id="current-ingress">读取中</strong></div>
      <div class="metric"><span>验证进度</span><strong id="progress">0 / 9</strong></div>
    </section>

    <div class="guide">
      <div><h2>验证点</h2><p>第 7 项需要先获得两条浏览器路径证据</p></div>
      <span class="counter" id="status-counter">0 / 9 通过</span>
    </div>
    <section class="steps" id="steps"></section>

    <section class="final" id="final">
      <div><strong>9 / 9 全部通过</strong><div class="description">完整证据链：监听语义 → loopback → eth0 → eth1 → 双路径交叉证明 → UDP → 服务重启</div></div>
      <button class="reset" id="reset">重新演示</button>
    </section>
  </main>

  <script>
    const STEP_DEFINITIONS = [
      { id: "wildcard_listener", kind: "GUEST", title: "确认 INADDR_ANY 通配监听", description: "读取真实 Flask listener 的 bind 与 getsockname 结果。", expected: "bind=0.0.0.0 且 getsockname=0.0.0.0:8080", mode: "server" },
      { id: "implicit_listen", kind: "GUEST", title: "确认 listen() 隐式绑定", description: "新建未 bind 的 TCP socket，直接 listen() 后观察内核分配的端点。", expected: "0.0.0.0:<非零临时端口>", mode: "server" },
      { id: "reuse_address", kind: "GUEST", title: "确认 SO_REUSEADDR", description: "读取 Flask listener 的真实 socket option。", expected: "SO_REUSEADDR=1", mode: "server" },
      { id: "loopback_tcp", kind: "GUEST", title: "验证 loopback 服务路径", description: "在 guest 内经 127.0.0.1 访问同一个通配 listener。", expected: "accepted=127.0.0.1:8080 且收到 65536 bytes", mode: "server" },
      { id: "browser_eth0", kind: "BROWSER", title: "浏览器穿过 18080 → eth0", description: "当前浏览器直接请求宿主机 18080，经 QEMU hostfwd 命中第一张 VirtIO 网卡。", expected: "accepted=10.0.2.15:8080，响应体 65536 bytes", mode: "browser", path: { interface: "eth0", guestAddress: "10.0.2.15", frontendPort: 18080 } },
      { id: "browser_eth1", kind: "BROWSER", title: "浏览器穿过 18081 → eth1", description: "当前浏览器直接请求宿主机 18081，经另一条 QEMU hostfwd 命中第二张 VirtIO 网卡。", expected: "accepted=10.0.3.15:8080，响应体 65536 bytes", mode: "browser", path: { interface: "eth1", guestAddress: "10.0.3.15", frontendPort: 18081 } },
      { id: "browser_compare", kind: "CROSS CHECK", title: "交叉证明：一进程、一 listener、两路径", description: "对比前两步的独立浏览器证据，排除启动了两个服务的可能。", expected: "相同 PID + 相同 0.0.0.0:8080 + 不同 accepted 地址", mode: "compare" },
      { id: "udp_multi_interface", kind: "GUEST", title: "验证 UDP 通配绑定跨接口收发", description: "一个 UDP 0.0.0.0 socket 依次通过 lo、eth0、eth1 接收数据。", expected: "三条地址路径全部收到原始 payload", mode: "server" },
      { id: "same_port_restart", kind: "GUEST", title: "关闭后立即同端口重启", description: "关闭临时服务 listener，立即在完全相同的端口重新 bind 并提供响应。", expected: "第一次服务关闭；第二次同端口监听成功", mode: "server" },
    ];

    const state = { proofs: new Map(), running: new Set() };
    const stepsRoot = document.getElementById("steps");

    function element(tag, className, text) {
      const node = document.createElement(tag);
      if (className) node.className = className;
      if (text !== undefined) node.textContent = text;
      return node;
    }

    function renderSteps() {
      stepsRoot.replaceChildren();
      STEP_DEFINITIONS.forEach((definition, index) => {
        const proof = state.proofs.get(definition.id);
        const card = element("article", "step");
        card.id = `step-${definition.id}`;
        if (state.running.has(definition.id)) card.classList.add("running");
        else if (proof) card.classList.add(proof.status.toLowerCase());
        else card.classList.add("ready");

        card.appendChild(element("div", "number", String(index + 1).padStart(2, "0")));
        const copy = element("div", "step-copy");
        const title = element("div", "step-title");
        title.append(element("strong", "", definition.title), element("span", "kind", definition.kind));
        copy.append(title, element("p", "description", definition.description), element("div", "expect", `期望：${definition.expected}`));
        card.appendChild(copy);

        const buttonLabel = state.running.has(definition.id)
          ? "正在执行"
          : proof ? "重新执行本项" : "执行本项";
        const button = element("button", "run-step", buttonLabel);
        button.disabled = state.running.has(definition.id);
        button.addEventListener("click", () => executeStep(definition));
        card.appendChild(button);

        const evidence = element("div", "evidence");
        if (proof) {
          const comparison = element("div", "comparison");
          const expected = element("div", "proof");
          expected.append(element("span", "", "EXPECTED"), element("code", "", proof.expected));
          const observed = element("div", "proof");
          observed.append(element("span", "", "OBSERVED"), element("code", "", proof.observed));
          comparison.append(expected, observed);
          const evidenceLabel = definition.mode === "browser"
            ? "Flask 辅助日志；硬证据请看宿主机 QEMU_PCAP_EVIDENCE"
            : "被测应用解释日志；syscall 最终证据以独立 C regression 为准";
          const label = element("div", "terminal-label");
          label.append(element("span", "", evidenceLabel), element("b", "", proof.status));
          evidence.append(comparison, label, element("pre", "", proof.line));
        }
        card.appendChild(evidence);
        stepsRoot.appendChild(card);
      });

      const passed = [...state.proofs.values()].filter((proof) => proof.status === "PASS").length;
      document.getElementById("progress").textContent = `${passed} / ${STEP_DEFINITIONS.length}`;
      document.getElementById("status-counter").textContent = `${passed} / ${STEP_DEFINITIONS.length} 通过`;
      document.getElementById("final").classList.toggle("show", passed === STEP_DEFINITIONS.length);
    }

    function hostForPort(port) {
      const hostname = window.location.hostname.includes(":") ? `[${window.location.hostname}]` : window.location.hostname;
      return `${window.location.protocol}//${hostname}:${port}`;
    }

    async function executeServerStep(definition) {
      const response = await fetch("/api/demo/step", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ step: definition.id }),
      });
      const result = await response.json();
      return { ...result.evidence, line: result.line };
    }

    async function executeBrowserStep(definition) {
      const token = `step-${definition.path.interface}-${Date.now().toString(36)}`;
      const query = new URLSearchParams({ path: definition.path.interface, token });
      const response = await fetch(`${hostForPort(definition.path.frontendPort)}/api/demo/path-proof?${query}`, { cache: "no-store", mode: "cors" });
      const bytes = new Uint8Array(await response.arrayBuffer());
      const prefix = new TextDecoder().decode(bytes.slice(0, token.length));
      const serverStatus = response.headers.get("X-Asterinas-Step-Status");
      const acceptedAddress = response.headers.get("X-Asterinas-Accepted-Address");
      const acceptedPort = response.headers.get("X-Asterinas-Accepted-Port");
      const listener = response.headers.get("X-Asterinas-Listener");
      const pid = Number(response.headers.get("X-Asterinas-Pid"));
      const serverLine = response.headers.get("X-Asterinas-Step-Evidence") || "终端证据头缺失";
      const passed = response.status === 200
        && serverStatus === "PASS"
        && bytes.length === 65536
        && prefix === token
        && acceptedAddress === definition.path.guestAddress
        && acceptedPort === "8080";
      return {
        accepted_address: acceptedAddress,
        expected: definition.expected,
        line: serverLine,
        listener,
        observed: `HTTP=${response.status} token=${prefix} bytes=${bytes.length} accepted=${acceptedAddress}:${acceptedPort} listener=${listener} pid=${pid}`,
        pid,
        source: "browser",
        status: passed ? "PASS" : "FAIL",
        step: definition.id,
      };
    }

    async function executeCompareStep(definition) {
      const proofs = [state.proofs.get("browser_eth0"), state.proofs.get("browser_eth1")].filter(Boolean);
      const response = await fetch("/api/demo/browser-compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ proofs }),
      });
      const result = await response.json();
      return { ...result.evidence, line: result.line };
    }

    async function executeStep(definition) {
      state.running.add(definition.id);
      renderSteps();
      let proof;
      try {
        if (definition.mode === "server") proof = await executeServerStep(definition);
        else if (definition.mode === "browser") proof = await executeBrowserStep(definition);
        else proof = await executeCompareStep(definition);
      } catch (error) {
        proof = {
          expected: definition.expected,
          observed: String(error),
          line: `flask_socket_demo: STEP_EVIDENCE {"step":"${definition.id}","status":"FAIL","observed":"browser request failed"}`,
          status: "FAIL",
          step: definition.id,
        };
      }
      state.proofs.set(definition.id, proof);
      state.running.delete(definition.id);
      renderSteps();
      document.getElementById(`step-${definition.id}`).scrollIntoView({ behavior: "smooth", block: "center" });
    }

    async function loadRuntime() {
      const [statusResponse, requestResponse] = await Promise.all([
        fetch("/api/status", { cache: "no-store" }),
        fetch("/request-info", { cache: "no-store" }),
      ]);
      const status = await statusResponse.json();
      const requestInfo = await requestResponse.json();
      document.getElementById("pid").textContent = `PID ${status.pid}`;
      document.getElementById("listener").textContent = `${status.listener.address}:${status.listener.port}`;
      document.getElementById("current-ingress").textContent = `${requestInfo.host} → ${requestInfo.local_address}:${requestInfo.local_port}`;
    }

    document.getElementById("reset").addEventListener("click", () => {
      state.proofs.clear();
      renderSteps();
      window.scrollTo({ top: 0, behavior: "smooth" });
    });

    renderSteps();
    loadRuntime().catch((error) => {
      document.getElementById("current-ingress").textContent = `读取失败：${error}`;
    });
  </script>
</body>
</html>
"""
