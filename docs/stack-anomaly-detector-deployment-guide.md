# Stack Anomaly Detector 部署运维指南

## 1. 环境要求

| 组件 | 最低版本 | 说明 |
|------|---------|------|
| JDK | 1.8+ | 编译目标 1.8，兼容 JDK 8/11/17 |
| Tomcat | 8.5 / 9.x | 其他 Servlet 容器需单独验证 |
| 磁盘空间 | 50MB | Agent JAR + 告警日志（默认模式约 22KB/h） |

## 2. 部署步骤

### 2.1 放置 Agent JAR

```bash
# 将 JAR 复制到目标服务器
cp stack-anomaly-detector-1.0.0-shaded.jar /opt/rasp/
```

### 2.2 配置 Tomcat JVM 参数

编辑 `$CATALINA_BASE/bin/setenv.sh`（或 Windows 下 `setenv.bat`）：

```bash
# Linux - 使用 JAVA_OPTS 而非 CATALINA_OPTS
# CATALINA_OPTS 会被 catalina.sh 通过 eval 处理，导致分号被解释为 shell 命令分隔符
export JAVA_OPTS="\
  -javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar=block.mode=monitor;learning.duration=600000 \
  -Drasp.sm.delay=30"
```

```bat
REM Windows
set JAVA_OPTS=-javaagent:C:\rasp\stack-anomaly-detector-1.0.0-shaded.jar=block.mode=monitor;learning.duration=600000 -Drasp.sm.delay=30
```

### 2.3 重启 Tomcat

```bash
$CATALINA_BASE/bin/catalina.sh stop
$CATALINA_BASE/bin/catalina.sh start
```

### 2.4 验证部署

检查 `catalina.out` 中应出现以下日志：

```
[StackAnomalyDetector] Agent initialized with args: block.mode=monitor;learning.duration=600000
[StackAnomalyDetector] RASP SecurityManager 已安装 (替换默认管理器)
[StackAnomalyDetector] Bytecode transformer registered successfully
```

确认 Tomcat 内置应用正常访问：

```bash
curl -I http://localhost:8080/examples/
# 预期: HTTP/1.1 200 OK
```

## 3. 参数说明

### 3.1 Agent 参数（-javaagent 等号后，分号分隔）

| 参数 | 默认值 | 说明 |
|------|-------|------|
| `block.mode` | `monitor` | `monitor` 仅告警不阻断；`block` 告警且阻断操作 |
| `learning.duration` | `300000` (5分钟) | 学习期时长（毫秒）。此期间所有操作只学习不告警，确保正常业务调用栈被录入基线 |
| `debug.log` | `false` | `true` 输出完整调试日志（含每次文件操作和调用栈详情，用于排查误报） |
| `verbose.info` | `false` | `true` 恢复 INFO 级别日志写入文件（仅当 `debug.log=true` 时有意义） |

### 3.2 JVM 系统属性（-D 参数）

| 参数 | 默认值 | 说明 |
|------|-------|------|
| `rasp.sm.delay` | `15` | SecurityManager 延迟安装秒数（给 Tomcat 预留启动时间）。若 `/examples` 等内置应用返回 404，增大此值 |
| `rasp.sm.immediate` | `false` | 设为 `true` 则立即安装 SecurityManager（非 Tomcat 环境如 Spring Boot 独立 JAR） |

### 3.3 检测模型参数（代码级，需重新编译修改）

| 参数 | 位置 | 默认值 | 说明 |
|------|------|-------|------|
| `HIGH_RISK_THRESHOLD` | `TemporalGuard.java` | `50` | 高风险阈值，>= 此值触发 block/monitor |
| `MEDIUM_RISK_THRESHOLD` | `TemporalGuard.java` | `20` | 中风险阈值，>= 此值触发 alarm |
| `MIN_NORMAL_PROBABILITY` | `BaselineLearningEngine.java` | `0.01` | CTPG 最低正常概率，低于此值触发 +35 |
| `STARTUP_PERIOD_MS` | `BaselineLearningEngine.java` | `120_000` | 启动期时长，此期间指纹记为启动指纹 |
| 敏感文件字典 | `TemporalGuard.java:analyzeFileSensitivity()` | 分级评分 | +60/+50/+40/+30/+20 五个级别 |
| 敏感命令字典 | `TemporalGuard.java:analyzeCommand()` | 命令评分 | whoami/+20, ls/+10, date/+5 等 |

## 4. 学习期说明（重要）

### 4.1 工作原理

Agent 采用**纯白名单基线模型**，分为两个阶段：

```
┌──────────────────────────────────────┐     ┌─────────────────────────┐
│           学习期                      │     │       检测期             │
│    (learning.duration)               │ ──> │    (持续运行)            │
│                                      │     │                         │
│  beforeService/afterService:         │     │  beforeService/afterService:
│    仅 2xx/3xx 响应触发的操作学习      │     │    记录请求上下文          │
│    404/403 扫描器流量不计入基线       │     │                         │
│                                      │     │  所有操作:               │
│  所有操作只学习不告警                 │     │    未知指纹 + 未知转移    │
│  记录调用栈指纹（过滤 RASP 内部帧）   │     │    → SSF + CTPG 评分     │
│  建立 CTPG 方法转移图                 │     │    → 超过阈值告警/阻断    │
└──────────────────────────────────────┘     └─────────────────────────┘
```

**学习期扫描器流量过滤**：系统通过 ASM 字节码 Hook 在 `HttpServlet.service()` 中注入 `beforeService(req)` 和 `afterService(req, res)` 钩子。`afterService` 检查 HTTP 响应状态码，仅对 2xx/3xx（成功响应）触发的操作进行学习。404/403 等扫描器响应不会建立基线指纹，避免扫描器噪声污染基线。

检测维度：
- **调用栈指纹 (SSF)**：整个调用栈的哈希指纹是否在基线库中（RASP 内部帧已过滤）
- **方法转移图 (CTPG)**：方法 A → 方法 B 的调用关系是否出现过（RASP 内部帧已过滤，只追踪业务代码转移）
- **线程轨迹 (TTT)**：单线程内的操作序列是否异常
- **危险调用特征**：是否包含 Runtime.exec、反射+文件 IO 等组合
- **敏感路径匹配**：`analyzeFileSensitivity` 分级评分（+20 ~ +60）代替简单布尔值，确保高敏感文件必定命中阈值
- **HTTP 上下文保护 (isNonSensitiveDefaultServletAccess)**：检测期 HTTP 请求中 DefaultServlet/JspServlet 对非敏感文件的访问直接跳过检测

### 4.2 评分与告警

| 分数区间 | 行为 | 说明 |
|---------|------|------|
| < 20 | 无动作 | 正常业务操作 |
| 20 ~ 49 | 告警日志 | 写入 `stack-anomaly-alerts.log` |
| >= 50 | 告警或阻断 | 取决于 `block.mode` |

**评分组成**：

| 评分项 | 加分 | 触发条件 |
|--------|------|---------|
| SSF 指纹未知 | +30 | 调用栈哈希不在学习基线中 |
| SSF 相似度过低 | +20 | 与所有已知指纹的最大 LCS 相似度 < 0.3 |
| CTPG 转移未知 | +35 | 某对 (source → target) 在 TRANSITION_GRAPH 中不存在或概率 < 0.01 |
| CTPG 转移偏低 | +15 | 概率 < 0.1 |
| TTT 轨迹异常 | +20 × N | Web→IO 直连、反射深度异常、可疑转移序列 |
| checkSensitiveFileAccess | +30 | 文件路径含 /etc/passwd、web.xml 等通用敏感关键字 |
| checkDangerousClasses | +20 × N | 调用栈含 Runtime.exec、FileInputStream、ClassLoader 等 |
| analyzeFileSensitivity | +20 ~ +60 | 文件路径分级匹配（/etc/passwd=+60, web.xml=+50, .env=+40 等） |
| analyzeCommand | +5 ~ +20 | 命令分级评分（whoami=+20, ls=+10, date=+5） |
| 反射+文件IO组合 | +30 | 调用栈中同时出现反射调用和文件 I/O |

### 4.3 为什么学习期至关重要

学习期内发生的所有操作（包括正常业务和 Webshell 攻击）都会写入基线。
学习期结束后：

- **学习中已覆盖的操作**：SSF 指纹已知 + CTPG 转移已知，评分 < 20，静默放行
- **学习中未覆盖的操作**：基线缺失 → SSF 未知(+30) + CTPG 未知(+35) = 最低 65 分，必定告警

> 如果某类正常业务操作（如文件上传、报表导出）在学习期内从未发生，
> 学习期后首次出现时会直接命中告警阈值。

### 4.4 建议的学习期策略

#### 策略 A：延长学习期（推荐）

将 `learning.duration` 设置到足够覆盖一次完整的业务周期：

```
learning.duration=1800000   # 30 分钟，确保所有定时任务也执行一次
learning.duration=3600000   # 60 分钟，覆盖小时级定时任务
```

#### 策略 B：人为触发覆盖

在学习期内，通过自动化脚本或手动操作，执行一次完整的业务流程：
- 用户注册/登录
- 文件上传/下载
- 报表导出
- 后台管理操作
- 第三方 API 调用

```bash
# 示例：用 curl 触发关键业务路径
curl -X POST http://localhost:8080/app/upload -F "file=@test.txt"
curl http://localhost:8080/app/export?type=report
curl -X POST http://localhost:8080/app/admin/config -d "..."
```

#### 策略 C：JSP 预编译 + 静态资源预加载（Tomcat 环境）

Tomcat 的 JSP 编译器 (Jasper) 在首次编译 JSP 文件时会触发类加载操作（`ClassLoader.loadClass`），如果在检测期发生，会被 `checkDangerousClasses` 误报为 `DangerousClass`。此外，`DefaultServlet` 处理静态资源（目录列表、HTML 文件）的调用栈模式如未在学习期覆盖，检测期首次出现时 CTPG 会产生告警。

建议：学习期内访问所有 JSP 页面和关键静态资源，使其一次编译并学习：

```bash
# JSP 预编译 - 访问应用中的所有 JSP 页面
for jsp in readfile.jsp listdir.jsp writefile.jsp exec.jsp; do
  curl -s "http://localhost:8080/your-app/$jsp"
done

# 静态资源预加载 - 学习 DefaultServlet 调用模式
for page in "/index.html" "/static/style.css"; do
  curl -s "http://localhost:8080$page"
done

# 目录列表预加载 - 学习目录浏览的 DefaultServlet 模式
curl -s http://localhost:8080/examples/
```

> JSP 编译噪声：如果学习期未预编译 JSP，检测期访问 JSP 时，Jasper 的 JDT 编译器类加载（`org.eclipse.jdt.internal.compiler.*`）会产生大量 `DangerousClass: ClassLoader.loadClass` 告警，在调试模式下可达数千行日志，甚至导致 Tomcat OOM。

## 5. 告警日志

### 5.1 日志级别与默认行为

| 日志级别 | 默认生产 | `debug.log=true` | `verbose.info=true` | 写入条件 |
|---------|---------|-----------------|--------------------|---------|
| `DEBUG` | 不写 | 写入文件 | 写入文件 | 每次操作触发、学习事件等高频日志 |
| `INFO` | 不写 | 不写 | 写入文件 | 不常用 |
| `WARN` | 写入文件 | 写入文件 | 写入文件 | 学习完成、摘要统计、初始化 |
| `ALARM` | 写入文件 | 写入文件 | 写入文件 | 异常检测命中 |
| `BLOCK` | 写入文件 | 写入文件 | 写入文件 | 阻断操作触发 |
| `ERROR` | 写入文件 | 写入文件 | 写入文件 | 异常错误 |

### 5.2 日志量预估

| 模式 | 典型日志量 | 说明 |
|------|----------|------|
| **默认生产模式** | ~22 KB/h | 仅写告警 + 每分钟一条摘要 + 学习完成通知 |
| Debug 模式 | 按需可变 | 每次操作和调用栈全部写入，仅排查时开启 |

### 5.3 摘要日志

默认模式下不输出每次操作日志，改为每分钟汇总一条统计行：

```
[2026-06-17 01:12:44.017] [WARN] [摘要] 近60秒: 文件读取=0 文件写入=0 文件删除=0 命令执行=0 HTTP请求=27 学习事件=26
```

### 5.4 日志位置

告警日志写入 Tomcat 工作目录下的 `stack-anomaly-alerts.log`：

```
$CATALINA_BASE/stack-anomaly-alerts.log
```

### 5.5 日志格式

```
# 初始化
[2026-06-17 01:11:24.881] [WARN] [RaspSecurityManager] 初始化成功

# 学习完成
[2026-06-17 01:11:49.875] [WARN] [BaselineLearning] 基线学习完成，进入检测模式。指纹数=27 转移图大小=136

# 每分钟摘要
[2026-06-17 01:12:44.017] [WARN] [摘要] 近60秒: 文件读取=156 文件写入=12 文件删除=0 命令执行=0 HTTP请求=42 学习事件=38

# 告警事件
[2026-06-17 01:15:01.940] [ALARM] [RaspSecurityManager] 中风险文件写入: 分数=35, 文件=/opt/tomcat/webapps/ROOT/index.jsp
[2026-06-17 01:15:01.941] [ALARM] [MONITOR-ONLY] 高风险时空异常: 分数=65, 文件=/etc/passwd (仅告警模式)
```

### 5.6 日志轮转

建议配置 `logrotate` 管理告警日志大小：

```bash
# /etc/logrotate.d/stack-anomaly
/opt/tomcat/stack-anomaly-alerts.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    copytruncate
}
```

## 6. 阻断模式切换

### 6.1 从 monitor 切换到 block

经充分验证确认无误报后，可切换为阻断模式：

```bash
# 修改 setenv.sh 中的 agent 参数
-javaagent:...jar=block.mode=block;learning.duration=600000
```

### 6.2 阻断行为

当 `block.mode=block` 且异常评分 >= 50 时：

- 文件操作：抛出 `SecurityException`，操作被 JDK 拒绝
- 命令执行：抛出 `SecurityException`，进程创建被拒绝
- `block.mode=monitor` 时：仅写入 `[MONITOR-ONLY]` 告警日志，操作正常执行

### 6.3 切换建议

```
monitor (部署初期 1~2 周)
  → 观察告警日志，确认无误报
  → 覆盖所有正常业务操作到基线
  → 切换到 block
```

## 7. 故障排查

### 7.1 参数未生效（catalina.sh eval 问题）

若使用 `CATALINA_OPTS` 传递 agent 参数且参数包含分号，`catalina.sh` 的 `eval` 会将分号解释为 shell 命令分隔符，导致参数被截断。
表现为日志中 `Agent initialized with args` 后面的参数不完整。

解决方案：将 `CATALINA_OPTS` 改为 `JAVA_OPTS`（不会被 eval），或直接使用 `java` 命令启动。

### 7.2 /examples 等内置应用返回 404

确认 `-Drasp.sm.delay` 值足够大（建议 >= 15），确保 SecurityManager 在 Tomcat 完全启动后再安装。

### 7.3 告警日志中出现大量正常业务操作

说明学习期内未覆盖该操作。处理方式：

1. 延长学习期并重启，让该操作被学入基线
2. 使用策略 C（JSP 预编译 + 静态资源预加载）确保 Tomcat 内部操作被覆盖
3. 或者在告警分析中人工加白该类型的操作模式

### 7.4 扫描器 404 探测导致大量误报

**症状**：HTTP 扫描器发送 404 探测请求后，告警日志中出现大量 `CTPG 异常转移` 和 `MONITOR-ONLY` 告警。

**原因分析**：
- 扫描器 404 探测（如 `/wp-admin`, `/phpmyadmin`）经过 Tomcat `DefaultServlet` 时仍会触发 `checkRead`（文件存在性检查）
- 学习期的 `beforeService`/`afterService` 机制已过滤 404 响应不计入基线
- 检测期 `isNonSensitiveDefaultServletAccess` 对非敏感文件路径自动跳过检测

**排查步骤**：
1. 确认 Tomcat 版本支持 `HttpServlet.service()` 字节码注入 — 检查日志中是否有 `beforeService 被调用` 的 DEBUG 记录（需 `debug.log=true`）
2. 若通用路径（如 `/nonexistent`）触发告警，确认 `isNonSensitiveDefaultServletAccess` 中 `analyzeFileSensitivity` 返回 0（路径不匹配任何敏感关键字）
3. 若 `.env`、`application.properties` 等敏感路径触发告警，这是**正确行为** — 这些路径包含凭据/配置关键字，应产生告警

**注意**：通用 404 扫描器路径（如 wp-admin, phpmyadmin, backup 等）已被过滤为零误报。仅安全敏感性路径（/.env, /config/application.properties, /WEB-INF/web.xml）会继续告警。

### 7.5 SecurityManager 未生效

检查 `catalina.out` 中是否包含：

```
RASP SecurityManager 已安装
```

若缺失，检查 JVM 是否支持 SecurityManager（JDK 17 需设置 `-Djava.security.manager=allow`，JDK 24+ 已移除）。

### 7.6 JSP 编译期产生大量 DangerousClass 告警

**症状**：检测期首次访问 JSP 页面时，告警日志暴增，出现大量 `[DangerousClass] ClassLoader.loadClass` 告警，甚至导致 Tomcat OOM。

**原因**：Jasper (Tomcat JSP 引擎) 使用 Eclipse JDT 编译器进行 JSP 源码编译，编译过程触发大量类加载，每次 `ClassLoader.loadClass` 都被 `checkDangerousClasses` 检测为危险操作。

**解决**：在学习期内预编译所有 JSP（参见策略 C）。JDT 编译器类加载在学习期不计入告警。也可使用 Tomcat 的 JSP 预编译功能：
```bash
# Tomcat JSP 预编译（Jasper 的 jspc 工具）
$CATALINA_HOME/bin/jspc.sh -webapp /path/to/webapp
```

### 7.7 日志量仍然过大

确认未误开启 `debug.log=true`。默认生产模式下日志量为约 22 KB/h。若需要在排查期间启用详细日志，排查完成后务必关闭：
移除 agent arg 中的 `debug.log=true` 并重启。

### 7.8 排查流程

```
1. 确认 Agent 加载: grep "Agent initialized" catalina.out
2. 确认 SecurityManager 安装: grep "SecurityManager 已安装" catalina.out
3. 确认 webapp 部署: grep "Server startup" catalina.out
4. 确认检测生效: tail -f stack-anomaly-alerts.log
5. 扫描器噪声排查: 加 debug.log=true 参数，观察 beforeService/afterService DEBUG 日志
6. JSP 编译噪声排查: 检查 DangerousClass 告警的时间戳是否与首次 JSP 访问对齐
7. 调试模式排查: 加 debug.log=true 参数重启后查看详细日志
```

## 8. 卸载

```bash
# 1. 移除 setenv.sh 中的 -javaagent 参数
# 2. 重启 Tomcat
$CATALINA_BASE/bin/catalina.sh stop
$CATALINA_BASE/bin/catalina.sh start
```

---

**版本**: 1.0.0  
**更新日期**: 2026-06-22
