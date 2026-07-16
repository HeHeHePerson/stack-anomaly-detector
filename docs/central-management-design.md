# 集中管理方案设计

## 1. 架构概述

```
┌──────────┐  syslog UDP 5514   ┌──────────────────────┐
│ Agent 1  │ ──────────────────>│                      │
└──────────┘                    │   Central Manager    │
┌──────────┐  heartbeat HTTP    │   ┌──────────────┐  │
│ Agent 2  │ ──────────────────>│   │ Flask Web    │  │
└──────────┘                    │   │ (port 5100)  │  │
┌──────────┐  config pull HTTP  │   └──────┬───────┘  │
│ Agent N  │ <──────────────────│          │          │
└──────────┘                    │   ┌──────┴───────┐  │
                                │   │ SQLite DB    │  │
                                │   └──────────────┘  │
                                         │
                                ┌────────┴────────┐
                                │  Admin Browser   │
                                │  http://host:5100 │
                                └──────────────────┘
```

## 2. 通信通道

| 通道 | 方向 | 协议 | 端口 | 用途 |
|------|------|------|------|------|
| Syslog | Agent → Manager | UDP | 5514 | 告警实时转发 (RFC 5424 + JSON) |
| Heartbeat | Agent → Manager | HTTP POST | 5100 | 心跳、状态上报、基线摘要 |
| Config Pull | Agent → Manager | HTTP GET | 5100 | 拉取最新配置 |
| Fingerprint Bans Pull | Heartbeat 响应中携带 | HTTP | 5100 | 随心跳响应返回全局封禁指纹 |
| Web Console | Admin → Manager | HTTP | 5100 | 管理界面 |

## 3. 数据模型

### agents
| 字段 | 类型 | 说明 |
|------|------|------|
| id | TEXT PK | agent_id (hostname:catalina_base) |
| hostname | TEXT | 主机名 |
| ip | TEXT | Agent 来源 IP |
| version | TEXT | Agent 版本 |
| block_mode | TEXT | 当前阻断模式 |
| learning_done | INTEGER | 学习是否完成 (0/1) |
| fingerprint_count | INTEGER | 累计指纹数 |
| alert_count | INTEGER | 累计告警数 |
| last_heartbeat | TEXT | 最后心跳时间 |
| config_version | INTEGER | 已应用的配置版本号 |
| baseline_size | INTEGER | 基线文件大小 (bytes) |
| registered_at | TEXT | 首次注册时间 |

### alerts
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增 ID |
| agent_id | TEXT | 来源 Agent |
| type | TEXT | 告警类型 (ALARM/BLOCK/FP-BAN/CORRELATION) |
| message | TEXT | 告警内容 (含原始日志) |
| score | INTEGER | 风险分数 |
| stack_trace | TEXT | 调用栈 (预留) |
| remote_addr | TEXT | 客户端 IP |
| url | TEXT | 告警文件路径或 URL |
| fingerprint | TEXT | 浏览器指纹 (FP:xxx) |
| created_at | TEXT | 时间戳 |

### fingerprint_bans
| 字段 | 类型 | 说明 |
|------|------|------|
| fingerprint | TEXT PK | 指纹哈希 |
| reason | TEXT | 封禁原因 |
| source_agent | TEXT | 触发封禁的 Agent |
| banned_at | TEXT | 封禁时间 |
| expires_at | TEXT | 过期时间 |

### configurations
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增 ID |
| version | INTEGER UNIQUE | 版本号 (自增) |
| config_json | TEXT | 配置 JSON (key-value) |
| description | TEXT | 变更说明 |
| created_at | TEXT | 创建时间 |
| active | INTEGER | 是否为当前生效配置 |

## 4. REST API

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/v1/heartbeat | Agent 心跳上报 |
| GET | /api/v1/config | Agent 拉取配置 (返回最新版本) |
| GET | /api/v1/fingerprint-bans | 拉取全局封禁指纹列表 |
| POST | /api/v1/fingerprint-bans | 手动添加指纹封禁 |
| DELETE | /api/v1/fingerprint-bans/:fp | 解除指纹封禁 |
| GET | /api/v1/alerts | 查询告警 (支持 agent_id/type/limit 过滤) |
| DELETE | /api/v1/alerts | 删除告警 (ids 参数为逗号分隔 ID 列表, 无参则全量清空) |
| GET | /api/v1/alerts/export | 导出告警为 CSV (BOM UTF-8, 支持过滤参数) |
| GET | /api/v1/agents | Agent 列表 (含在线/离线状态) |
| POST | /api/v1/agents | 手动添加 Agent 节点 |
| DELETE | /api/v1/agents/:id | 删除 Agent 节点及关联告警 |
| POST | /config/publish | Web 控制台发布新配置 |

## 5. Syslog 告警转发

### Agent 端 (ForwardManager)

Agent 通过 `AlertLogger.forwardAlert()` 将告警实时转发。配置参数:

| 参数 | 说明 | 默认值 |
|------|------|--------|
| forward.type | 转发类型: syslog / kafka / none | (不设置则不启用) |
| forward.syslog.host | syslog 服务器地址 | localhost |
| forward.syslog.port | syslog 服务器端口 | 514 |
| forward.app.name | 应用名称 (出现在心跳和告警中) | rasp-agent |

### 传输格式

```
<134>1 2026-07-16T12:00:00.000+0000 hostname raspt-forwarder - - - {"type":"alert","app":"tomcat85","timestamp":"1752645472201","level":"ALARM","prefix":"[DangerousClass]","message":"...[完整告警消息]..."}
```

- PRI = 134 (local0.info)
- 消息体为 JSON, 包含 type/app/timestamp/level/prefix/message 字段
- Manager 端解析 JSON 提取告警信息, 通过来源 IP 匹配已注册的 Agent

### Manager 端处理

- UDP 接收器监听指定端口, 解码后提取 JSON 负载
- 通过来源 IP + app 名称匹配已注册 Agent (优先按 IP 匹配, 最后心跳时间排序)
- 插入 `alerts` 表, 同步更新 `agents` 表的 alert_count/block_count

## 6. Agent 端改动

- `HeartbeatReporter`: 新增组件, Timer 定时 (30s) HTTP POST 心跳到 Central Manager
- `AgentConfig`: 新增 `manager.url`、`manager.token` 参数
- `AgentMain.startHeartbeatReporter()`: 获取 hostname 并启动心跳; 若 DNS 解析失败则 fallback 到 `$USER-agent`
- 心跳携带 `agent_id`、`hostname`、`version`、`block_mode`、`learning_done`、`fingerprint_count`、`baseline_size`、`alert_count`、`block_count`
- Manager 响应可携带 `config_update`、`config_version`、`fingerprint_bans` 列表

## 7. Web 控制台

| 页面 | 功能 |
|------|------|
| 仪表盘 (/) | Agent 总数、在线数、今日告警、今日封禁统计; 最近告警列表; **告警勾选删除/全量清空** |
| Agent 页 (/agents) | 所有 Agent 列表, 在线/离线状态, 最后心跳时间; **手动添加/删除节点** |
| 告警页 (/alerts) | 告警列表, 支持按 Agent/类型/时间过滤, 分页; **勾选删除/全量清空/导出 CSV** |
| 指纹页 (/fingerprints) | 全局指纹封禁列表, 支持解除封禁、手动添加 |
| 配置页 (/config) | 发布新配置 (JSON key-value), 查看历史版本 |

## 8. 部署

```bash
# 1. 安装依赖
pip install -r tools/central-manager/requirements.txt

# 2. 启动 Central Manager
python3 tools/central-manager/server.py --port 5100 --syslog-port 5514

# 3. Agent 启动参数 (在 setenv.sh 中配置)
CATALINA_OPTS="-javaagent:stack-anomaly-detector.jar=...,manager.url=http://HOST:5100,forward.type=syslog,forward.syslog.host=HOST,forward.syslog.port=5514,forward.app.name=myapp"
```

## 9. 单机 testcase 测试配置

将 Central Manager 和 Tomcat Agent 部署在同一台机器上, 用于快速验证全链路。

### 9.1 步骤

```bash
# 1. 启动 Central Manager (后台)
cd /workspace && python3 tools/central-manager/server.py --port 5100 --syslog-port 5514 &

# 2. 构建并部署 Agent
mvn clean package -DskipTests -q
cp target/stack-anomaly-detector-1.0.0-shaded.jar /opt/tomcat85/stack-anomaly-detector.jar

# 3. 配置 Tomcat Agent
cat > /opt/tomcat85/bin/setenv.sh << 'EOF'
CATALINA_OPTS="-javaagent:/opt/tomcat85/stack-anomaly-detector.jar=\
learning.duration=5000,\
block.mode=block,\
debug.log=true,\
fp.ban.threshold=3,\
fp.ban.window=30,\
fp.ban.duration=60,\
manager.url=http://127.0.0.1:5100,\
forward.type=syslog,\
forward.syslog.host=127.0.0.1,\
forward.syslog.port=5514,\
forward.app.name=tomcat85"
EOF

# 4. 重启 Tomcat
/opt/tomcat85/bin/shutdown.sh
/opt/tomcat85/bin/startup.sh
```

### 9.2 验证

```bash
# 等待学习完成并触发基线访问
sleep 6 && curl -s -o /dev/null 'http://localhost:8080/examples/index.html'

# 发起攻击
curl -s -o /dev/null 'http://localhost:8080/examples/sm_attack.jsp?action=read'

# 检查 Agent 注册
curl -s 'http://localhost:5100/api/v1/agents' | python3 -m json.tool

# 查看告警
curl -s 'http://localhost:5100/api/v1/alerts?limit=5' | python3 -m json.tool

# 检查 Agent 心跳
grep 'Heartbeat\|心跳' /opt/tomcat85/logs/catalina.out | tail -3
```

### 9.3 期望结果

- `POST /api/v1/heartbeat` 返回 `status=ok`
- Agent 列表中显示 `root-agent:/opt/tomcat85`, `block_mode=BLOCK`, `alerts>0`
- 告警列表中每条子检测器告警均携带非零 score (如 `[DangerousClass] 分数=+20`, `[CTPG] 分数=+35`)
- BLOCK 告警 score=160 为累计总分
- Web 控制台 `http://localhost:5100` 仪表盘可正常访问

### 9.4 测试用攻击 JSP

部署于 `/opt/tomcat85/webapps/examples/`:

| JSP | 参数 | 操作 |
|-----|------|------|
| `sm_attack.jsp` | `?action=read` | FileInputStream 读取 /etc/passwd |
| `sm_attack.jsp` | `?action=exec` | Runtime.exec 执行命令 |
| `sm_rb.jsp` | — | ResourceBundle 文件探测 |
| `sm_file.jsp` | — | File.exists 文件检测 |

## 10. 关键设计决策

- **单文件部署**: Flask + SQLite + syslog 接收器全部集成在 `server.py` 中, 无需外部数据库或独立进程
- **告警 Agent 匹配**: syslog 通过来源 IP 匹配已注册的 Agent, 解决 agent_id 不一致问题 (syslog 中的 app 名与心跳 agent_id 格式不同)
- **心跳响应携带配置**: Agent 每次心跳时 Manager 在响应中告知是否有配置更新及全局指纹封禁列表, 无需额外 API 调用
- **非特权端口**: syslog 使用 5514 而非标准 514 端口 (避免 root 权限要求)
