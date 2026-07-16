#!/usr/bin/env python3
"""
RASP Central Manager — 集中管理服务端

功能：
  1. Syslog 告警接收 (UDP 514)
  2. Agent 心跳 / 配置拉取 (HTTP API)
  3. Web 管理控制台
  4. SQLite 数据持久化

启动：
  python3 server.py --port 5100 --syslog-port 514

首次运行自动创建 SQLite 数据库。
"""

import argparse
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db")

# ── 数据库 ──────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            id          TEXT PRIMARY KEY,
            hostname    TEXT,
            ip          TEXT,
            version     TEXT,
            block_mode  TEXT DEFAULT 'MONITOR',
            learning_done INTEGER DEFAULT 0,
            fingerprint_count INTEGER DEFAULT 0,
            alert_count INTEGER DEFAULT 0,
            block_count INTEGER DEFAULT 0,
            last_heartbeat TEXT,
            config_version INTEGER DEFAULT 0,
            baseline_size INTEGER DEFAULT 0,
            registered_at TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT,
            type        TEXT,
            message     TEXT,
            score       INTEGER DEFAULT 0,
            stack_trace TEXT,
            remote_addr TEXT,
            url         TEXT,
            fingerprint TEXT,
            created_at  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_time  ON alerts(created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_type  ON alerts(type);

        CREATE TABLE IF NOT EXISTS fingerprint_bans (
            fingerprint TEXT PRIMARY KEY,
            reason      TEXT,
            source_agent TEXT,
            banned_at   TEXT,
            expires_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS configurations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            version     INTEGER UNIQUE,
            config_json TEXT,
            description TEXT,
            created_at  TEXT,
            active      INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()

# ── Syslog 接收器 ───────────────────────────────────────

SYSLOG_PATTERN = re.compile(
    r'<\d+>.*?\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\]'
    r'\s*\[(\w+)\]\s*(\[.*?\]|)\s*(.*)'
)

AGENT_ID_PATTERN = re.compile(r'\[agent=([^\]]+)\]')

def handle_syslog(data, addr):
    try:
        text = data.decode("utf-8", errors="replace").strip()
        json_match = re.search(r'\{.*"type"\s*:\s*"alert".*\}', text)
        if not json_match:
            m = SYSLOG_PATTERN.search(text)
            if not m:
                return
            timestamp, level, tag, message = m.group(1), m.group(2), m.group(3), m.group(4)
            agent_match = AGENT_ID_PATTERN.search(text)
            agent_id = agent_match.group(1) if agent_match else f"{addr[0]}:unknown"
            alert_type = tag.strip("[]") if tag else "UNKNOWN"
        else:
            payload = json.loads(json_match.group(0))
            level = payload.get("level", "UNKNOWN")
            alert_type = level
            message = payload.get("message", "")
            app_name = payload.get("app", f"{addr[0]}:unknown")
            timestamp = payload.get("timestamp", "")
            if timestamp.isdigit():
                timestamp = datetime.utcfromtimestamp(int(timestamp) / 1000).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            conn = get_db()
            matched = conn.execute(
                "SELECT id FROM agents WHERE ip = ? OR id = ? ORDER BY last_heartbeat DESC LIMIT 1",
                (addr[0], app_name)
            ).fetchone()
            agent_id = matched["id"] if matched else app_name
            conn.close()

        if alert_type in ("ALARM", "BLOCK", "FP-BAN", "CORRELATION"):
            score_match = re.search(r'分数=[\+]*(\d+)', message)
            score = int(score_match.group(1)) if score_match else 0

            addr_match = re.search(r'IP\s+(\S+)', message)
            remote_addr = addr_match.group(1) if addr_match else ""

            url_match = re.search(r'文件=(\S+)|URL\s*=\s*(\S+)', message)
            url = (url_match.group(1) or url_match.group(2) or "") if url_match else ""

            fp_match = re.search(r'FP:\s*(\S+)', message)
            fingerprint = fp_match.group(1) if fp_match else ""

            conn = get_db()
            conn.execute(
                "INSERT INTO alerts (agent_id, type, message, score, remote_addr, url, fingerprint, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (agent_id, alert_type, message, score, remote_addr, url, fingerprint, timestamp)
            )

            if alert_type == "BLOCK":
                conn.execute("UPDATE agents SET block_count = block_count + 1 WHERE id = ?", (agent_id,))
            else:
                conn.execute("UPDATE agents SET alert_count = alert_count + 1 WHERE id = ?", (agent_id,))

            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[Syslog] 解析错误: {e}", file=sys.stderr)

def start_syslog_receiver(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)
    print(f"[Syslog] 监听 UDP/{port}")

    def loop():
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                handle_syslog(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Syslog] 错误: {e}", file=sys.stderr)

    t = threading.Thread(target=loop, daemon=True)
    t.start()

# ── Flask Web ───────────────────────────────────────────

from flask import Flask, request, jsonify, render_template_string, g

app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(__file__), "templates"))

@app.before_request
def before_request():
    g.db = get_db()

@app.teardown_request
def teardown_request(exc):
    if hasattr(g, "db"):
        g.db.close()

# ── Agent API ───────────────────────────────────────────

@app.route("/api/v1/heartbeat", methods=["POST"])
def heartbeat():
    data = request.get_json(force=True, silent=True) or {}
    agent_id = data.get("agent_id", f"{request.remote_addr}:unknown")
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    existing = g.db.execute("SELECT id FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if existing:
        g.db.execute("""
            UPDATE agents SET
                hostname = ?, ip = ?, version = ?, block_mode = ?,
                learning_done = ?, fingerprint_count = ?, baseline_size = ?,
                last_heartbeat = ?
            WHERE id = ?
        """, (
            data.get("hostname", ""), request.remote_addr, data.get("version", ""),
            data.get("block_mode", "MONITOR"), data.get("learning_done", 0),
            data.get("fingerprint_count", 0), data.get("baseline_size", 0),
            now, agent_id
        ))
    else:
        g.db.execute("""
            INSERT INTO agents (id, hostname, ip, version, block_mode, last_heartbeat, registered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (agent_id, data.get("hostname", ""), request.remote_addr,
              data.get("version", ""), data.get("block_mode", "MONITOR"), now, now))

    config_version = data.get("config_version", 0)
    latest = g.db.execute(
        "SELECT version FROM configurations WHERE active = 1 ORDER BY version DESC LIMIT 1"
    ).fetchone()
    latest_version = latest["version"] if latest else 0

    bans = g.db.execute(
        "SELECT fingerprint, reason, expires_at FROM fingerprint_bans WHERE expires_at > ?",
        (now,)
    ).fetchall()

    g.db.commit()

    return jsonify({
        "status": "ok",
        "config_update": latest_version > config_version,
        "config_version": latest_version,
        "fingerprint_bans": [
            {"fingerprint": r["fingerprint"], "reason": r["reason"], "expires_at": r["expires_at"]}
            for r in bans
        ]
    })

@app.route("/api/v1/config", methods=["GET"])
def get_config():
    version = request.args.get("version", "0")
    latest = g.db.execute(
        "SELECT * FROM configurations WHERE active = 1 ORDER BY version DESC LIMIT 1"
    ).fetchone()
    if not latest or latest["version"] <= int(version):
        return jsonify({"status": "unchanged", "version": int(version)})

    return jsonify({
        "status": "updated",
        "version": latest["version"],
        "config": json.loads(latest["config_json"])
    })

@app.route("/api/v1/fingerprint-bans", methods=["GET"])
def get_fingerprint_bans():
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    bans = g.db.execute(
        "SELECT fingerprint, reason, expires_at FROM fingerprint_bans WHERE expires_at > ?",
        (now,)
    ).fetchall()
    return jsonify([{"fingerprint": r["fingerprint"], "expires_at": r["expires_at"]} for r in bans])

@app.route("/api/v1/fingerprint-bans/<fp>", methods=["DELETE"])
def unban_fingerprint(fp):
    g.db.execute("DELETE FROM fingerprint_bans WHERE fingerprint = ?", (fp,))
    g.db.commit()
    return jsonify({"status": "ok"})

@app.route("/api/v1/agents", methods=["GET"])
def list_agents():
    agents = g.db.execute("SELECT * FROM agents ORDER BY last_heartbeat DESC").fetchall()
    return jsonify([dict(r) for r in agents])

@app.route("/api/v1/alerts", methods=["GET"])
def list_alerts():
    agent = request.args.get("agent", "")
    atype = request.args.get("type", "")
    limit = min(int(request.args.get("limit", "100")), 1000)

    sql = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if agent:
        sql += " AND agent_id = ?"
        params.append(agent)
    if atype:
        sql += " AND type = ?"
        params.append(atype)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    alerts = g.db.execute(sql, params).fetchall()
    return jsonify([dict(r) for r in alerts])

# ── Agent 端上报指纹封禁 ─────────────────────────────────

@app.route("/api/v1/fingerprint-bans", methods=["POST"])
def report_fingerprint_ban():
    data = request.get_json(force=True, silent=True) or {}
    fp = data.get("fingerprint", "")
    if not fp:
        return jsonify({"status": "error", "message": "missing fingerprint"}), 400

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    expires = (datetime.utcnow() + timedelta(seconds=data.get("duration", 300))).strftime("%Y-%m-%d %H:%M:%S")

    g.db.execute(
        "INSERT OR REPLACE INTO fingerprint_bans (fingerprint, reason, source_agent, banned_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (fp, data.get("reason", ""), data.get("agent_id", "unknown"), now, expires)
    )
    g.db.commit()
    return jsonify({"status": "ok"})

# ── 告警删除 / 导出 ─────────────────────────────────────

@app.route("/api/v1/alerts", methods=["DELETE"])
def delete_alerts():
    ids_param = request.args.get("ids", "")
    if ids_param:
        id_list = [int(x) for x in ids_param.split(",") if x.strip().isdigit()]
        if id_list:
            placeholders = ",".join("?" for _ in id_list)
            g.db.execute(
                f"DELETE FROM alerts WHERE id IN ({placeholders})", id_list
            )
    else:
        g.db.execute("DELETE FROM alerts")
    g.db.commit()
    return jsonify({"status": "ok", "deleted": g.db.total_changes})

@app.route("/api/v1/alerts/export")
def export_alerts():
    agent = request.args.get("agent", "")
    atype = request.args.get("type", "")

    sql = "SELECT a.*, ag.hostname FROM alerts a LEFT JOIN agents ag ON a.agent_id = ag.id WHERE 1=1"
    params = []
    if agent:
        sql += " AND a.agent_id = ?"
        params.append(agent)
    if atype:
        sql += " AND a.type = ?"
        params.append(atype)
    sql += " ORDER BY a.created_at DESC LIMIT 10000"

    alerts = g.db.execute(sql, params).fetchall()

    import csv, io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["时间", "节点", "类型", "内容", "分数", "来源IP", "指纹", "URL"])
    for r in alerts:
        writer.writerow([
            r["created_at"], r["hostname"] or r["agent_id"], r["type"],
            r["message"], r["score"], r["remote_addr"] or "",
            r["fingerprint"] or "", r["url"] or ""
        ])

    from flask import Response
    return Response(
        output.getvalue().encode("utf-8-sig"),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=rasp-alerts.csv"}
    )

# ── Agent 管理 (增/删) ───────────────────────────────────

@app.route("/api/v1/agents/<agent_id>", methods=["DELETE"])
def delete_agent(agent_id):
    g.db.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
    g.db.execute("DELETE FROM alerts WHERE agent_id = ?", (agent_id,))
    g.db.commit()
    return jsonify({"status": "ok"})

@app.route("/api/v1/agents", methods=["POST"])
def add_agent():
    data = request.get_json(force=True, silent=True) or {}
    agent_id = data.get("agent_id", "").strip()
    if not agent_id:
        return jsonify({"status": "error", "message": "agent_id required"}), 400
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    hostname = data.get("hostname", agent_id)
    ip_addr = data.get("ip", request.remote_addr)
    version = data.get("version", "-")
    block_mode = data.get("block_mode", "MONITOR")

    existing = g.db.execute("SELECT id FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if existing:
        g.db.execute(
            "UPDATE agents SET hostname=?, ip=?, version=?, block_mode=?, last_heartbeat=? WHERE id=?",
            (hostname, ip_addr, version, block_mode, now, agent_id)
        )
    else:
        g.db.execute(
            "INSERT INTO agents (id, hostname, ip, version, block_mode, last_heartbeat, registered_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (agent_id, hostname, ip_addr, version, block_mode, now, now)
        )
    g.db.commit()
    return jsonify({"status": "ok"})

# ── Web 控制台 ──────────────────────────────────────────

BASE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RASP Central Manager</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1119;color:#d0d4e0}
.nav{background:#161829;border-bottom:1px solid #1e2358;padding:0 24px;display:flex;align-items:center;height:52px}
.nav a{color:#8890b5;text-decoration:none;padding:0 16px;font-size:14px;line-height:52px;border-bottom:2px solid transparent}
.nav a:hover{color:#c0c8f0}
.nav a.active{color:#fff;border-bottom-color:#4a6cf7}
.nav .brand{color:#fff;font-size:16px;font-weight:600;margin-right:32px}
.main{padding:24px;max-width:1400px;margin:0 auto}
.card{background:#151829;border:1px solid #1e2358;border-radius:8px;padding:20px;margin-bottom:16px}
.card h2{font-size:16px;color:#8890b5;margin-bottom:16px;font-weight:500}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 12px;color:#6670a0;font-weight:500;border-bottom:1px solid #1e2358}
td{padding:8px 12px;border-bottom:1px solid #151d30;color:#b0b8d0}
tr:hover td{background:#1a1e35}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:500}
.badge-ok{background:#0d2818;color:#4ade80}
.badge-warn{background:#2d1b0e;color:#f59e0b}
.badge-danger{background:#2d0f14;color:#f87171}
.badge-info{background:#0d1830;color:#60a5fa}
.btn{padding:6px 14px;border-radius:4px;font-size:12px;cursor:pointer;border:1px solid #2a3060;background:#1a2040;color:#b0b8d0}
.btn:hover{background:#222850;color:#fff}
.btn-danger{background:#3d1520;border-color:#5a2030;color:#f87171}
.btn-danger:hover{background:#4d2030}
.mono{font-family:'Courier New',monospace;font-size:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:#151829;border:1px solid #1e2358;border-radius:8px;padding:16px}
.stat-card .label{font-size:12px;color:#6670a0;margin-bottom:4px}
.stat-card .value{font-size:28px;font-weight:600;color:#fff}
.flash{background:#0d2818;border:1px solid #1a5a30;color:#4ade80;padding:10px 16px;border-radius:6px;margin-bottom:16px;font-size:13px}
.flash-err{background:#2d0f14;border:1px solid #5a2030;color:#f87171;padding:10px 16px;border-radius:6px;margin-bottom:16px;font-size:13px}
.toolbar{display:flex;gap:8px;margin-bottom:12px;align-items:center;flex-wrap:wrap}
.spacer{flex:1}
</style>
<script>
function selAll(cls, cb) { document.querySelectorAll('.'+cls).forEach(c => c.checked = cb.checked); }
function getSelected(cls) { return [...document.querySelectorAll('.'+cls+':checked')].map(c => c.value); }

function delAlerts(all) {
    if (!confirm(all ? '确认清空全部告警？此操作不可逆！' : '确认删除选中的告警？')) return;
    var ids = all ? '' : getSelected('alert-cb').join(',');
    fetch('/api/v1/alerts?ids='+ids, {method:'DELETE'})
    .then(r=>r.json()).then(d=>{ alert('已删除 '+d.deleted+' 条告警'); location.reload(); });
}

function exportAlerts() {
    var q = new URLSearchParams(location.search);
    location.href = '/api/v1/alerts/export?' + q.toString();
}

function delAgent(id) {
    if (!confirm('确认删除节点 '+id+'？关联告警也将被清除。')) return;
    fetch('/api/v1/agents/'+encodeURIComponent(id), {method:'DELETE'})
    .then(r=>r.json()).then(d=>{ alert('已删除'); location.reload(); });
}

function addAgent() {
    var id = document.getElementById('new-agent-id').value.trim();
    var host = document.getElementById('new-agent-host').value.trim();
    var ip = document.getElementById('new-agent-ip').value.trim();
    if (!id) { alert('Agent ID 不能为空'); return; }
    fetch('/api/v1/agents', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({agent_id:id, hostname:host||id, ip:ip||''})
    }).then(r=>r.json()).then(d=>{
        if (d.status=='ok') { alert('节点已添加'); location.reload(); }
        else { alert('失败: '+(d.message||'')); }
    });
}
</script>
</head>
<body>
<div class="nav">
  <span class="brand">RASP Central Manager</span>
  <a href="/" class="{{ 'active' if page=='dashboard' else '' }}">仪表盘</a>
  <a href="/agents" class="{{ 'active' if page=='agents' else '' }}">节点管理</a>
  <a href="/alerts" class="{{ 'active' if page=='alerts' else '' }}">告警中心</a>
  <a href="/fingerprints" class="{{ 'active' if page=='fingerprints' else '' }}">指纹封禁</a>
  <a href="/config" class="{{ 'active' if page=='config' else '' }}">配置管理</a>
</div>
<div class="main">{{ content|safe }}</div>
</body>
</html>"""

@app.route("/")
def dashboard():
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    total_agents = g.db.execute("SELECT COUNT(*) as c FROM agents").fetchone()["c"]
    online_agents = g.db.execute(
        "SELECT COUNT(*) as c FROM agents WHERE last_heartbeat > datetime('now','-2 minutes')"
    ).fetchone()["c"]

    today_start = datetime.utcnow().strftime("%Y-%m-%d 00:00:00")
    total_alerts = g.db.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE created_at >= ?", (today_start,)
    ).fetchone()["c"]
    total_blocks = g.db.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE type='BLOCK' AND created_at >= ?", (today_start,)
    ).fetchone()["c"]

    banned_fps = g.db.execute(
        "SELECT COUNT(*) as c FROM fingerprint_bans WHERE expires_at > ?", (now,)
    ).fetchone()["c"]

    recent_alerts = g.db.execute(
        "SELECT a.*, ag.hostname FROM alerts a LEFT JOIN agents ag ON a.agent_id = ag.id "
        "ORDER BY a.created_at DESC LIMIT 20"
    ).fetchall()

    content = f"""
    <div class="stats">
      <div class="stat-card"><div class="label">在线节点</div><div class="value">{online_agents}<span style="font-size:14px;color:#6670a0">/{total_agents}</span></div></div>
      <div class="stat-card"><div class="label">今日告警</div><div class="value">{total_alerts}</div></div>
      <div class="stat-card"><div class="label">今日阻断</div><div class="value" style="color:#f87171">{total_blocks}</div></div>
      <div class="stat-card"><div class="label">封禁指纹</div><div class="value">{banned_fps}</div></div>
    </div>
    <div class="card">
       <h2>最近告警</h2>
      <div class="toolbar">
        <button class="btn btn-danger" onclick="delAlerts(false)">删除选中</button>
        <button class="btn btn-danger" onclick="delAlerts(true)">清空全部</button>
        <span class="spacer"></span>
        <span style="font-size:12px;color:#6670a0">共 {len(recent_alerts)} 条</span>
      </div>
      <table>
        <tr><th style="width:32px"><input type="checkbox" onchange="selAll('alert-cb',this)"></th><th>时间</th><th>节点</th><th>类型</th><th>内容</th><th>IP</th></tr>
        {''.join(f'''<tr>
          <td><input type="checkbox" class="alert-cb" value="{r["id"]}"></td>
          <td class="mono">{r["created_at"][11:19] if r["created_at"] else ""}</td>
          <td>{r["hostname"] or r["agent_id"][:20]}</td>
          <td><span class="badge {'badge-danger' if r['type']=='BLOCK' else 'badge-warn' if r['type']=='FP-BAN' else 'badge-info'}">{r["type"]}</span></td>
          <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{r["message"][:80]}</td>
          <td class="mono">{r["remote_addr"] or "-"}</td>
        </tr>''' for r in recent_alerts)}
      </table>
    </div>"""

    return render_template_string(BASE_HTML, page="dashboard", content=content)

@app.route("/agents")
def agents_page():
    agents = g.db.execute("SELECT * FROM agents ORDER BY last_heartbeat DESC").fetchall()
    now = datetime.utcnow()
    rows = []
    for a in agents:
        hb = a["last_heartbeat"] or ""
        online = False
        if hb:
            try:
                hb_dt = datetime.strptime(hb, "%Y-%m-%d %H:%M:%S")
                online = (now - hb_dt).total_seconds() < 120
            except:
                pass
        badge = '<span class="badge badge-ok">在线</span>' if online else '<span class="badge badge-warn">离线</span>'
        rows.append(f'''<tr>
          <td>{a["hostname"] or a["id"][:30]}</td>
          <td class="mono">{a["id"]}</td>
          <td class="mono">{a["ip"]}</td>
          <td>{a["version"] or "-"}</td>
          <td>{a["block_mode"]}</td>
          <td>{badge}</td>
          <td class="mono">{hb[11:19] if hb else "-"}</td>
          <td>{a["alert_count"]}</td>
          <td style="color:#f87171">{a["block_count"]}</td>
          <td><button class="btn btn-danger" onclick="delAgent('{a["id"]}')">删除</button></td>
        </tr>''')

    content = f"""<div class="card"><h2>节点列表</h2>
    <table><tr><th>主机名</th><th>Agent ID</th><th>IP</th><th>版本</th><th>模式</th><th>状态</th><th>最后心跳</th><th>告警</th><th>阻断</th><th>操作</th></tr>
    {''.join(rows)}</table></div>
    <div class="card">
      <h2>添加节点</h2>
      <div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">
        <div><label style="display:block;font-size:12px;color:#6670a0;margin-bottom:4px">Agent ID</label>
          <input id="new-agent-id" placeholder="必填" style="background:#0d1130;border:1px solid #2a3060;color:#b0b8d0;padding:8px 12px;border-radius:4px;width:200px"></div>
        <div><label style="display:block;font-size:12px;color:#6670a0;margin-bottom:4px">主机名</label>
          <input id="new-agent-host" placeholder="选填" style="background:#0d1130;border:1px solid #2a3060;color:#b0b8d0;padding:8px 12px;border-radius:4px;width:160px"></div>
        <div><label style="display:block;font-size:12px;color:#6670a0;margin-bottom:4px">IP</label>
          <input id="new-agent-ip" placeholder="选填" style="background:#0d1130;border:1px solid #2a3060;color:#b0b8d0;padding:8px 12px;border-radius:4px;width:160px"></div>
        <button class="btn" onclick="addAgent()" style="background:#1a3050;border-color:#2a5080;color:#60a5fa;height:36px">添加</button>
      </div>
    </div>"""

    return render_template_string(BASE_HTML, page="agents", content=content)

@app.route("/alerts")
def alerts_page():
    agent_filter = request.args.get("agent", "")
    type_filter = request.args.get("type", "")

    sql = "SELECT a.*, ag.hostname FROM alerts a LEFT JOIN agents ag ON a.agent_id = ag.id WHERE 1=1"
    params = []
    if agent_filter:
        sql += " AND a.agent_id = ?"
        params.append(agent_filter)
    if type_filter:
        sql += " AND a.type = ?"
        params.append(type_filter)
    sql += " ORDER BY a.created_at DESC LIMIT 200"

    alerts = g.db.execute(sql, params).fetchall()
    agents = g.db.execute("SELECT DISTINCT agent_id FROM alerts").fetchall()

    types = ["", "ALARM", "BLOCK", "FP-BAN", "CORRELATION"]

    filter_html = f'''<div style="margin-bottom:16px;display:flex;gap:12px;align-items:center">
      <select onchange="location.search='agent='+this.value+'&type='+document.getElementById('tf').value" style="background:#1a2040;border:1px solid #2a3060;color:#b0b8d0;padding:6px 12px;border-radius:4px">
        <option value="">全部节点</option>
        {''.join(f'<option value="{a["agent_id"]}" {"selected" if agent_filter==a["agent_id"] else ""}>{a["agent_id"][:30]}</option>' for a in agents)}
      </select>
      <select id="tf" onchange="location.search='agent='+document.getElementById('af').value+'&type='+this.value" style="background:#1a2040;border:1px solid #2a3060;color:#b0b8d0;padding:6px 12px;border-radius:4px">
        {''.join(f'<option value="{t}" {"selected" if type_filter==t else ""}>{t or "全部类型"}</option>' for t in types)}
      </select>
    </div>'''

    rows = ''.join(f'''<tr>
      <td><input type="checkbox" class="alert-cb" value="{r["id"]}"></td>
      <td class="mono">{r["created_at"][:19] if r["created_at"] else ""}</td>
      <td>{r["hostname"] or r["agent_id"][:20]}</td>
      <td><span class="badge {'badge-danger' if r['type']=='BLOCK' else 'badge-warn' if r['type']=='FP-BAN' else 'badge-info'}">{r["type"]}</span></td>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{r["message"][:100]}</td>
      <td>{r["score"]}</td>
      <td class="mono">{r["remote_addr"] or "-"}</td>
    </tr>''' for r in alerts)

    content = f"""<div class="card"><h2>告警中心</h2>
    {filter_html}
    <div class="toolbar">
      <button class="btn btn-danger" onclick="delAlerts(false)">删除选中</button>
      <button class="btn btn-danger" onclick="delAlerts(true)">清空全部</button>
      <span class="spacer"></span>
      <button class="btn" onclick="exportAlerts()" style="background:#1a3050;border-color:#2a5080;color:#60a5fa">导出 CSV</button>
    </div>
    <table><tr><th style="width:32px"><input type="checkbox" onchange="selAll('alert-cb',this)"></th><th>时间</th><th>节点</th><th>类型</th><th>内容</th><th>分数</th><th>来源IP</th></tr>
    {rows}</table></div>"""

    return render_template_string(BASE_HTML, page="alerts", content=content)

@app.route("/fingerprints")
def fingerprints_page():
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    msg = ""

    if request.method == "POST" or (hasattr(request, 'form') and request.form):
        pass

    banned = g.db.execute(
        "SELECT * FROM fingerprint_bans WHERE expires_at > ? ORDER BY banned_at DESC", (now,)
    ).fetchall()

    rows = ''.join(f'''<tr>
      <td class="mono">{r["fingerprint"][:24]}</td>
      <td>{r["source_agent"][:30]}</td>
      <td>{r["reason"][:60]}</td>
      <td class="mono">{r["banned_at"][:19] if r["banned_at"] else ""}</td>
      <td class="mono">{r["expires_at"][:19] if r["expires_at"] else ""}</td>
      <td>
        <form method="POST" action="/fingerprints/{r['fingerprint']}/unban" style="display:inline">
          <button class="btn btn-danger" onclick="return confirm('确认解除封禁？')">解封</button>
        </form>
      </td>
    </tr>''' for r in banned)

    flash_html = f'<div class="flash">{msg}</div>' if msg else ""

    content = f"""<div class="card"><h2>指纹封禁列表</h2>
    {flash_html}
    <table><tr><th>指纹</th><th>来源节点</th><th>原因</th><th>封禁时间</th><th>过期时间</th><th>操作</th></tr>
    {rows or '<tr><td colspan="6" style="text-align:center;color:#6670a0;padding:24px">暂无封禁指纹</td></tr>'}</table></div>"""

    return render_template_string(BASE_HTML, page="fingerprints", content=content)

@app.route("/fingerprints/<fp>/unban", methods=["POST"])
def unban_fingerprint_web(fp):
    g.db.execute("DELETE FROM fingerprint_bans WHERE fingerprint = ?", (fp,))
    g.db.commit()
    return """<script>alert('已解除封禁');location.href='/fingerprints'</script>"""

@app.route("/config")
def config_page():
    msg = ""
    configs = g.db.execute("SELECT * FROM configurations ORDER BY version DESC").fetchall()
    current = g.db.execute("SELECT * FROM configurations WHERE active = 1 ORDER BY version DESC LIMIT 1").fetchone()

    config_list = ''.join(f'''<tr>
      <td>v{r["version"]}</td>
      <td>{r["description"] or "-"}</td>
      <td class="mono">{r["created_at"][:19] if r["created_at"] else ""}</td>
      <td>{'<span class="badge badge-ok">生效中</span>' if r["active"] else '<span class="badge badge-info">历史</span>'}</td>
    </tr>''' for r in configs)

    current_config = json.dumps(json.loads(current["config_json"]), indent=2, ensure_ascii=False) if current else "{}"

    flash_html = f'<div class="flash">{msg}</div>' if msg else ""

    content = f"""<div class="card"><h2>配置管理</h2>
    {flash_html}
    <h3 style="font-size:14px;color:#8890b5;margin-bottom:8px">当前生效配置</h3>
    <pre style="background:#0d1130;padding:16px;border-radius:6px;font-size:12px;overflow-x:auto;color:#b0b8d0;margin-bottom:16px">{current_config}</pre>
    <h3 style="font-size:14px;color:#8890b5;margin-bottom:8px">发布新配置</h3>
    <form method="POST" action="/config/publish" style="display:flex;flex-direction:column;gap:12px">
      <textarea name="config_json" rows="12" style="background:#0d1130;border:1px solid #2a3060;color:#b0b8d0;padding:12px;border-radius:6px;font-family:'Courier New',monospace;font-size:12px" placeholder='{{"block.mode":"block","fp.ban.threshold":5}}'></textarea>
      <div style="display:flex;gap:12px;align-items:center">
        <input name="description" placeholder="变更说明" style="flex:1;background:#0d1130;border:1px solid #2a3060;color:#b0b8d0;padding:8px 12px;border-radius:4px">
        <button class="btn" style="background:#1a3050;border-color:#2a5080;color:#60a5fa">发布配置</button>
      </div>
    </form>
    <h3 style="font-size:14px;color:#8890b5;margin:24px 0 8px">历史配置</h3>
    <table><tr><th>版本</th><th>说明</th><th>发布时间</th><th>状态</th></tr>
    {config_list}</table></div>"""

    return render_template_string(BASE_HTML, page="config", content=content)

@app.route("/config/publish", methods=["POST"])
def publish_config():
    try:
        config_json = request.form.get("config_json", "{}")
        json.loads(config_json)
    except json.JSONDecodeError:
        return """<script>alert('JSON 格式无效');location.href='/config'</script>"""

    description = request.form.get("description", "")
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    latest = g.db.execute("SELECT MAX(version) as v FROM configurations").fetchone()
    version = (latest["v"] or 0) + 1

    g.db.execute("UPDATE configurations SET active = 0 WHERE active = 1")
    g.db.execute(
        "INSERT INTO configurations (version, config_json, description, created_at, active) VALUES (?, ?, ?, ?, 1)",
        (version, config_json, description, now)
    )
    g.db.commit()
    return """<script>alert('配置 v{} 已发布');location.href='/config'</script>""".format(version)

# ── 启动入口 ────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="RASP Central Manager")
    parser.add_argument("--port", type=int, default=5100, help="Web 管理端口")
    parser.add_argument("--syslog-port", type=int, default=514, help="Syslog 监听端口")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="监听地址")
    args = parser.parse_args()

    init_db()
    start_syslog_receiver(args.syslog_port)

    print(f"[CentralManager] Web 控制台: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
