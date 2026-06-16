# Stack Anomaly Detector 部署运维指南

## 1. 环境要求

| 组件 | 最低版本 | 说明 |
|------|---------|------|
| JDK | 1.8+ | 编译目标 1.8，兼容 JDK 8/11/17 |
| Tomcat | 8.5 / 9.x | 其他 Servlet 容器需单独验证 |
| 磁盘空间 | 50MB | Agent JAR + 告警日志 |

## 2. 部署步骤

### 2.1 放置 Agent JAR

```bash
# 将 JAR 复制到目标服务器
cp stack-anomaly-detector-1.0.0-shaded.jar /opt/rasp/
```

### 2.2 配置 Tomcat JVM 参数

编辑 `$CATALINA_BASE/bin/setenv.sh`（或 Windows 下 `setenv.bat`）：

```bash
# Linux
export CATALINA_OPTS="\
  -javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar=block.mode=monitor,learning.duration=600000 \
  -Drasp.sm.delay=30"
```

```bat
REM Windows
set CATALINA_OPTS=-javaagent:C:\rasp\stack-anomaly-detector-1.0.0-shaded.jar=block.mode=monitor,learning.duration=600000 -Drasp.sm.delay=30
```

### 2.3 重启 Tomcat

```bash
$CATALINA_BASE/bin/catalina.sh stop
$CATALINA_BASE/bin/catalina.sh start
```

### 2.4 验证部署

检查 `catalina.out` 中应出现以下日志：

```
[StackAnomalyDetector] Agent initialized with args: block.mode=monitor,learning.duration=600000
[StackAnomalyDetector] SecurityManager 将在 30 秒后安装
[StackAnomalyDetector] RASP SecurityManager 已安装 (替换默认管理器)
```

确认 Tomcat 内置应用正常访问：

```bash
curl -I http://localhost:8080/examples/
# 预期: HTTP/1.1 200 OK
```

## 3. 参数说明

### Agent 参数（-javaagent 等号后，逗号分隔）

| 参数 | 默认值 | 说明 |
|------|-------|------|
| `block.mode` | `monitor` | `monitor` 仅告警不阻断；`block` 告警且阻断操作 |
| `learning.duration` | `300000` (5分钟) | 学习期时长（毫秒） |

### JVM 系统属性（-D 参数）

| 参数 | 默认值 | 说明 |
|------|-------|------|
| `rasp.sm.delay` | `15` | SecurityManager 延迟安装秒数（给 Tomcat 预留启动时间） |
| `rasp.sm.immediate` | `false` | 设为 `true` 则立即安装 SecurityManager（非 Tomcat 环境） |

## 4. 学习期说明（重要）

### 4.1 工作原理

Agent 采用**纯白名单基线模型**，分为两个阶段：

```
┌───────────────────────┐     ┌──────────────────────┐
│     学习期            │     │     检测期            │
│  (learning.duration)  │ ──> │  (持续运行)           │
│                       │     │                      │
│  所有操作只学习不告警  │     │  未知操作 = 异常告警   │
│  记录调用栈指纹       │     │  已知操作 = 正常放行   │
│  建立方法转移图       │     │                      │
└───────────────────────┘     └──────────────────────┘
```

检测维度：
- **调用栈指纹 (SSF)**：整个调用栈的哈希指纹是否在基线库中
- **方法转移图 (CTPG)**：方法 A → 方法 B 的调用关系是否出现过
- **线程轨迹 (TTT)**：单线程内的操作序列是否异常
- **危险调用特征**：是否包含 Runtime.exec、反射+文件 IO 等组合
- **敏感路径匹配**：操作目标是否命中 `/etc/`、`.key`、`passwd` 等

### 4.2 评分与告警

| 分数区间 | 行为 | 说明 |
|---------|------|------|
| < 20 | 无动作 | 正常业务操作 |
| 20 ~ 49 | 告警日志 | 写入 `stack-anomaly-alerts.log` |
| >= 50 | 告警或阻断 | 取决于 `block.mode` |

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

## 5. 告警日志

### 5.1 日志位置

告警日志写入 Tomcat 工作目录下的 `stack-anomaly-alerts.log`：

```
$CATALINA_BASE/stack-anomaly-alerts.log
```

### 5.2 日志格式

```
[2026-06-16 03:20:01.926] [INFO] [TemporalGuard] HTTP 请求: /examples/servlets/
[2026-06-16 03:20:01.939] [ALARM] [RaspSecurityManager] 中风险文件写入: 分数=35, 文件=/opt/tomcat/webapps/ROOT/index.jsp
[2026-06-16 03:20:01.940] [BLOCK]  [MONITOR-ONLY] 高风险时空异常: 分数=65, 文件=/etc/passwd (仅告警模式)
```

### 5.3 日志轮转

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
-javaagent:...jar=block.mode=block,learning.duration=600000
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

### 7.1 /examples 等内置应用返回 404

确认 `-Drasp.sm.delay` 值足够大（建议 >= 15），确保 SecurityManager 在 Tomcat 完全启动后再安装。

### 7.2 告警日志中出现大量正常业务操作

说明学习期内未覆盖该操作。处理方式：

1. 延长学习期并重启，让该操作被学入基线
2. 或者在告警分析中人工加白该类型的操作模式

### 7.3 SecurityManager 未生效

检查 `catalina.out` 中是否包含：

```
RASP SecurityManager 已安装
```

若缺失，检查 JVM 是否支持 SecurityManager（JDK 17 需设置 `-Djava.security.manager=allow`，JDK 24+ 已移除）。

### 7.4 排查流程

```
1. 确认 Agent 加载: grep "Agent initialized" catalina.out
2. 确认 SecurityManager 安装: grep "SecurityManager 已安装" catalina.out
3. 确认 webapp 部署: grep "Server startup" catalina.out
4. 确认检测生效: tail -f stack-anomaly-alerts.log
```

## 8. 卸载

```bash
# 1. 移除 setenv.sh 中的 -javaagent 参数
# 2. 重启 Tomcat
$CATALINA_BASE/bin/catalina.sh stop
$CATALINA_BASE/bin/catalina.sh start
```
