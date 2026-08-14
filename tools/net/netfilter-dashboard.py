#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

"""交互式演示使用的无依赖实时 dashboard 和控制器。"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


DEMO_PREFIX = "NETFILTER_DEMO "
SNAPSHOT_BEGIN = re.compile(r"^NETFILTER_DEMO snapshot-begin label=(\S+)")
SNAPSHOT_END = re.compile(r"^NETFILTER_DEMO snapshot-end label=(\S+)")
CHAIN_RE = re.compile(r"^chain (\S+) policy (\S+)")
RULE_RE = re.compile(r"^\s*rule (\d+) pkts (\d+) bytes (\d+) match (.*)")


def parse_pairs(text: str) -> Dict[str, str]:
    pairs: Dict[str, str] = {}
    for token in shlex.split(text):
        if "=" in token:
            key, value = token.split("=", 1)
            pairs[key] = value
    return pairs


def parse_snapshot(lines: Iterable[str]) -> Tuple[List[dict], Optional[str]]:
    table = "filter"
    chain = ""
    policy: Optional[str] = None
    rules: List[dict] = []
    for raw in lines:
        line = raw.rstrip("\n")
        match = re.match(r"^table (\S+)", line)
        if match:
            table, chain = match.group(1), ""
            continue
        match = CHAIN_RE.match(line)
        if match:
            chain, policy = match.group(1), match.group(2)
            continue
        match = RULE_RE.match(line)
        if not match or not chain:
            continue
        number, packets, byte_count, rest = match.groups()
        target_match = re.search(r"\btarget (\S+)", rest)
        rules.append({
            "table": table,
            "chain": chain,
            "number": int(number),
            "packets": int(packets),
            "bytes": int(byte_count),
            "match": rest,
            "target": target_match.group(1) if target_match else "-",
        })
    return rules, policy


def empty_state(log_path: Path) -> dict:
    return {
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "log": str(log_path),
        "complete": False,
        "topology": {
            "left": "10.0.2.2",
            "router_left": "10.0.2.15",
            "router_right": "10.0.3.15",
            "right": "10.0.3.2",
        },
        "step": {"id": "", "scenario": "", "title": "等待 QEMU", "status": "idle"},
        "scenarios": {name: {"name": name, "status": "PENDING"}
                      for name in ("filter", "conntrack", "nat")},
        "actions": [], "flows": [], "rules": [], "snapshots": {},
        "snapshot": "waiting", "message": "等待交互演示启动",
    }


def read_state(log_path: Path) -> dict:
    state = empty_state(log_path)
    if not log_path.exists():
        state["message"] = "日志尚未生成；先启动 demo-step，再打开控制台。"
        return state
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        state["message"] = f"无法读取日志：{exc}"
        return state

    snapshot_lines: List[str] = []
    snapshot_label: Optional[str] = None
    last_snapshot: Optional[str] = None
    for line in lines:
        if line.startswith(DEMO_PREFIX):
            begin = SNAPSHOT_BEGIN.match(line)
            if begin:
                snapshot_label, snapshot_lines = begin.group(1), []
                continue
            end = SNAPSHOT_END.match(line)
            if end:
                if snapshot_label == end.group(1):
                    rules, policy = parse_snapshot(snapshot_lines)
                    state["snapshots"][snapshot_label] = {"rules": rules, "policy": policy}
                    state["rules"] = rules
                    state["snapshot"] = snapshot_label
                    last_snapshot = snapshot_label
                    if policy:
                        state["policy"] = policy
                snapshot_label, snapshot_lines = None, []
                continue
            if snapshot_label is not None:
                snapshot_lines.append(line)
                continue

            pairs = parse_pairs(line[len(DEMO_PREFIX):])
            if pairs.get("step"):
                state["step"] = {
                    "id": pairs["step"],
                    "scenario": pairs.get("scenario", ""),
                    "title": pairs.get("title", pairs["step"]),
                    "status": pairs.get("status", ""),
                }
            if pairs.get("scenario") in state["scenarios"]:
                name = pairs["scenario"]
                phase = pairs.get("phase", "running")
                state["scenarios"][name]["status"] = "PASS" if phase == "end" else "RUNNING"
            if pairs.get("action"):
                action = dict(pairs)
                try:
                    action["rc"] = int(action.get("rc", "-1"))
                except ValueError:
                    action["rc"] = -1
                action["status"] = "PASS" if action["rc"] == 0 else "FAIL"
                state["actions"].append(action)
            if pairs.get("flow"):
                state["flows"].append(pairs)
            if pairs.get("complete") == "1":
                state["complete"] = True
        elif snapshot_label is not None:
            snapshot_lines.append(line)

    if last_snapshot:
        state["snapshot"] = last_snapshot
    state["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    state["message"] = ("演示已完成；可以选择快照回看规则和计数器。"
                         if state["complete"] else "演示暂停在当前步骤；使用按钮继续。")
    return state


class ControlChannel:
    """维护到 QEMU 演示串口 Socket 的单一客户端连接。"""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.connection: Optional[socket.socket] = None
        self.stop = False
        self.thread = threading.Thread(target=self._reader, daemon=True)
        self.thread.start()

    def _reader(self) -> None:
        while not self.stop:
            if self.connection is None:
                conn: Optional[socket.socket] = None
                try:
                    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    conn.settimeout(1.0)
                    conn.connect(str(self.path))
                    with self.lock:
                        self.connection = conn
                except OSError:
                    if conn is not None:
                        conn.close()
                    time.sleep(0.5)
                    continue
            try:
                assert self.connection is not None
                if not self.connection.recv(4096):
                    self._close()
            except (OSError, socket.timeout):
                if self.connection is not None:
                    self._close()

    def _close(self) -> None:
        with self.lock:
            if self.connection is not None:
                try:
                    self.connection.close()
                except OSError:
                    pass
                self.connection = None

    def send(self, command: str) -> Tuple[bool, str]:
        with self.lock:
            if self.connection is None:
                return False, "QEMU serial socket is not connected"
            try:
                self.connection.sendall((command.rstrip("\n") + "\n").encode())
                return True, command
            except OSError as exc:
                self.connection = None
                return False, str(exc)


HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Asterinas Netfilter Interactive Lab</title>
<style>
:root{color-scheme:dark;--bg:#09111f;--card:#12223a;--line:#2a4669;--text:#e8f0fb;--muted:#91a8c5;--green:#42dc91;--orange:#ffc36f;--red:#ff7184;--blue:#76b9ff}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,var(--bg),#102541);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}header{padding:20px 26px 12px;border-bottom:1px solid var(--line)}h1{margin:0;font-size:24px}.sub,.meta{color:var(--muted)}main{max-width:1500px;margin:auto;padding:16px 22px 38px}.grid{display:grid;gap:14px;grid-template-columns:repeat(12,1fr)}.card{background:#12223aee;border:1px solid var(--line);border-radius:12px;padding:14px}.topology,.controls,.rules,.actions{grid-column:span 12}.scenarios{grid-column:span 4}.flows{grid-column:span 8}h2{font-size:15px;margin:0 0 10px;color:#cbe0fa}.topo{display:flex;justify-content:center;align-items:center;gap:8px;flex-wrap:wrap}.node{border:1px solid #4777ad;background:#182f4e;border-radius:9px;padding:9px 14px;text-align:center;min-width:145px}.node strong{display:block;color:var(--blue);font-size:16px}.arrow{font-size:21px;color:var(--orange)}.badge{display:inline-block;border-radius:999px;padding:2px 8px;background:#273e5e;color:var(--muted);font-size:12px}.pass{background:#153e2e;color:var(--green)}.fail{background:#431e2b;color:var(--red)}.running{background:#49351d;color:var(--orange)}.waiting{background:#253d5d;color:var(--blue)}button,select{border:1px solid #4773a7;border-radius:7px;background:#183554;color:var(--text);padding:8px 11px;font:inherit}button{cursor:pointer}button:hover{background:#244a74}button:disabled{opacity:.55;cursor:wait}.controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.current{flex:1;min-width:240px}.flow{border-left:3px solid var(--blue);padding:6px 10px;margin:6px 0;background:#102039}.route,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #294463;vertical-align:top}th{color:var(--muted);font-weight:500}.empty{color:var(--muted);padding:12px 0}.message{color:var(--orange);margin-top:9px}@media(max-width:900px){.scenarios,.flows{grid-column:span 12}main{padding:12px}}
</style></head><body><header><h1>Asterinas Netfilter Interactive Lab</h1><div class="sub">按钮驱动 guest 内真实 iptables 操作：每一步都会更新规则快照、计数器和数据包流向。</div></header>
<main><div class="grid"><section class="card topology"><h2>IPv4 拓扑</h2><div id="topology" class="topo"></div><div id="message" class="message"></div></section>
<section class="card controls"><h2>演示控制</h2><div id="current" class="current"></div><button id="next">下一步</button><button id="reset">重置</button><select id="scenario"><option value="filter">执行过滤场景</option><option value="conntrack">执行连接跟踪场景</option><option value="nat">执行 NAT 场景</option><option value="all">执行全部场景</option></select><button id="run">执行场景</button></section>
<section class="card scenarios"><h2>场景状态</h2><div id="scenarios"></div></section><section class="card flows"><h2>数据包流向</h2><div id="flows"></div></section>
<section class="card rules"><h2>规则快照 <span id="snapshot" class="badge"></span></h2><label class="meta">选择快照：<select id="snapshot-select"></select></label><div id="rules"></div></section>
<section class="card actions"><h2>iptables 操作时间线</h2><div id="actions"></div></section></div></main>
<script>
let selectedSnapshot='';const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const badge=s=>`<span class="badge ${String(s).toLowerCase()}">${esc(s)}</span>`;
function render(s){const t=s.topology||{},step=s.step||{};document.getElementById('topology').innerHTML=`<div class="node"><strong>左端点</strong>${esc(t.left)}</div><div class="arrow">→</div><div class="node"><strong>Asterinas</strong>${esc(t.router_left)} ↔ ${esc(t.router_right)}</div><div class="arrow">→</div><div class="node"><strong>右端点</strong>${esc(t.right)}</div>`;document.getElementById('message').textContent=s.message||'';document.getElementById('current').innerHTML=`当前步骤：<b>${esc(step.title||'等待')}</b> ${badge(step.status||'idle')} <span class="meta">${esc(step.id||'')}</span>`;document.getElementById('scenarios').innerHTML=Object.values(s.scenarios||{}).map(x=>`<p>${esc(x.name)} ${badge(x.status)}</p>`).join('');const flows=(s.flows||[]).slice(-12).reverse();document.getElementById('flows').innerHTML=flows.length?flows.map(x=>`<div class="flow"><b>${esc(x.flow)}</b> ${badge(x.verdict||'INFO')}<div class="route">${esc(x.original||'')} → ${esc(x.translated||'')}</div><div class="meta">${esc(x.protocol||'')} · state ${esc(x.state||'')}</div></div>`).join(''):'<div class="empty">等待数据包流向</div>';const snaps=s.snapshots||{},names=Object.keys(snaps);if(!selectedSnapshot||!snaps[selectedSnapshot])selectedSnapshot=s.snapshot||names[names.length-1]||'';document.getElementById('snapshot-select').innerHTML=names.length?names.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join(''):'<option value="">waiting</option>';document.getElementById('snapshot-select').value=selectedSnapshot;document.getElementById('snapshot-select').onchange=e=>{selectedSnapshot=e.target.value;render(s)};document.getElementById('snapshot').textContent=`snapshot: ${selectedSnapshot||'waiting'}`;const rules=selectedSnapshot&&snaps[selectedSnapshot]?snaps[selectedSnapshot].rules:(s.rules||[]);document.getElementById('rules').innerHTML=rules.length?`<table><thead><tr><th>表</th><th>链</th><th>#</th><th>匹配</th><th>动作</th><th>计数器</th></tr></thead><tbody>${rules.map(r=>`<tr><td>${esc(r.table)}</td><td>${esc(r.chain)}</td><td>${esc(r.number)}</td><td class="mono">${esc(r.match)}</td><td>${esc(r.target)}</td><td>${esc(r.packets)} pkts / ${esc(r.bytes)} B</td></tr>`).join('')}</tbody></table>`:'<div class="empty">等待 /proc/netfilter_rules 快照</div>';const actions=(s.actions||[]).slice(-18).reverse();document.getElementById('actions').innerHTML=actions.length?`<table><thead><tr><th>操作</th><th>返回码</th><th>结果</th></tr></thead><tbody>${actions.map(a=>`<tr><td class="mono">${esc(a.action)}</td><td>${esc(a.rc)}</td><td>${badge(a.status)}</td></tr>`).join('')}</tbody></table>`:'<div class="empty">等待 iptables 操作</div>'}
async function refresh(){try{const r=await fetch('/api/state?t='+Date.now());render(await r.json())}catch(e){document.getElementById('message').textContent='dashboard 正在等待 QEMU'} }async function control(command){const buttons=document.querySelectorAll('button');buttons.forEach(b=>b.disabled=true);try{const r=await fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command})});const body=await r.json();if(!body.ok)document.getElementById('message').textContent=body.error}catch(e){document.getElementById('message').textContent=String(e)}finally{buttons.forEach(b=>b.disabled=false);refresh()}}document.getElementById('next').onclick=()=>control('next');document.getElementById('reset').onclick=()=>control('reset');document.getElementById('run').onclick=()=>control('scenario '+document.getElementById('scenario').value);refresh();setInterval(refresh,700);
</script></body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    log_path: Path
    controller: ControlChannel

    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/state":
            self._json(read_state(self.log_path))
        elif path in ("/", "/index.html"):
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/api/control":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            command = str(request.get("command", ""))
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"ok": False, "error": f"invalid request: {exc}"}, 400)
            return
        if command not in {"next", "reset", "scenario filter", "scenario conntrack",
                           "scenario nat", "scenario all"}:
            self._json({"ok": False, "error": "unsupported command"}, 400)
            return
        ok, detail = self.controller.send(command)
        self._json({"ok": ok, "command": detail} if ok else {"ok": False, "error": detail},
                   200 if ok else 409)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", default="stage-records/demo/netfilter-demo.log")
    parser.add_argument("--control-socket", default="stage-records/demo/netfilter-demo-step.sock")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    log_path = Path(args.log).expanduser().resolve()
    control = ControlChannel(Path(args.control_socket).expanduser().resolve())
    handler = type("ConfiguredDashboardHandler", (DashboardHandler,),
                   {"log_path": log_path, "controller": control})
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Asterinas Netfilter Lab: http://{args.host}:{args.port}/")
    print(f"Following log: {log_path}")
    print(f"Controlling QEMU socket: {control.path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        control.stop = True
        control._close()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
