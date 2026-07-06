# Java RASP 静默攻击检测系统 - 部署与使用说明

## 1. 系统概述

基于调用栈时空建模的 Java RASP 检测系统，用于检测和防御冰蝎 (Behinder) Webshell 等静默攻击。通过 Java Agent + SecurityManager 双重机制，实现文件访问、命令执行、反射调用等高危行为的实时检测与阻断。

## 2. 环境要求

- **JDK 版本**: 1.8 (目标应用运行环境)
- **构建环境**: Maven 3.6+
- **应用服务器**: Tomcat 8.5+ / Spring Boot Embedded Tomcat
- **安全权限**: 允许设置 SecurityManager (Tomcat 默认允许)

## 3. 构建与部署

### 3.1 构建 JAR

```bash
# 克隆项目
git clone <仓库地址>
cd stack-anomaly-detector

# 编译打包
mvn clean package -DskipTests

# 构建产物
ls -lh target/stack-anomaly-detector-1.0.0-shaded.jar
```

生成的 `stack-anomaly-detector-1.0.0-shaded.jar` 包含所有依赖（ASM、Logback），约 1.2MB。

### 3.2 部署路径

将构建好的 JAR 复制到目标服务器的固定目录：

```bash
# 建议目录结构
/opt/rasp/
└── stack-anomaly-detector-1.0.0-shaded.jar
```

确保 Tomcat 运行用户对 JAR 有读取权限：

```bash
chmod 644 /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar
```

## 4. 启动配置

### 4.1 Tomcat 部署方式（推荐）

编辑 Tomcat 的 `bin/setenv.sh` (Linux) 或 `bin/setenv.bat` (Windows)，添加 Java Agent 参数：

**Linux (setenv.sh)**:

```bash
# 使用 JAVA_OPTS 而非 CATALINA_OPTS
# CATALINA_OPTS 会被 catalina.sh 通过 eval 处理，导致参数中的分号被截断
JAVA_OPTS="$JAVA_OPTS -javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar"
```

**Windows (setenv.bat)**:

```bat
set JAVA_OPTS=%JAVA_OPTS% -javaagent:C:\opt\rasp\stack-anomaly-detector-1.0.0-shaded.jar
```

### 4.2 Spring Boot 部署方式

```bash
java -javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar -jar your-application.jar
```

### 4.3 通用启动参数（可配置）

可通过 Agent 参数配置运行行为：

**仅告警模式（推荐首周部署）**：
```bash
-javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar=block.mode=monitor
```
此模式下，即使检测到高风险攻击行为，也不会抛出 `SecurityException` 阻断请求，仅记录告警日志。适用于：
- 新部署初期观察误报情况
- 确认业务正常后再启用阻断

**阻断模式（生产环境推荐）**：
```bash
-javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar=block.mode=block
```
此模式下，高风险行为会直接抛出异常阻断请求。

**自定义学习时长**：
```bash
-javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar=learning.duration=600000
```
单位为毫秒，默认 300000（5 分钟）。

**组合参数**：
```bash
-javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar=block.mode=monitor;learning.duration=600000
```

**调试日志（仅排查时开启）**：
```bash
-javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar=block.mode=monitor;learning.duration=600000;debug.log=true;verbose.info=true
```

完整参数表：
| 参数 | 可选值 | 默认值 | 说明 |
|------|--------|--------|------|
| `block.mode` | `monitor`, `block` | `monitor` | 检测到高风险行为时是否阻断（`monitor`=仅告警不阻断） |
| `learning.duration` | 正整数（毫秒） | `300000` | 基线学习时长，此期间所有操作仅记录不告警 |
| `debug.log` | `true`, `false` | `false` | 输出完整调试日志（含每次文件操作和调用栈详情） |
| `verbose.info` | `true`, `false` | `false` | 恢复 INFO 级别日志写入文件（需配合 `debug.log=true`） |
| `baseline.report` | `true`, `false` | `true` | 学习结束后自动生成基线报告（`stack-anomaly-baseline-report.log`） |
| `url.freq.threshold` | 1.0 ~ 10.0 | `1.5` | URL 访问频率异常阈值（倍数），检测期速率超过基线速率 × 阈值时告警 |
| `url.param.threshold` | 100 ~ 1000 | `150` | URL 参数值长度异常阈值（百分比），参数值长度超过基线最大长度 × 阈值% 时告警 |
| `forward.type` | `syslog`, `kafka`, `none` | `none` | 告警和模型结果外发类型。`syslog` 使用 UDP RFC 5424 协议；`kafka` 需在 pom.xml 中添加 kafka-clients 依赖 |
| `forward.app.name` | 任意字符串 | `rasp-agent` | 应用实例标识。由用户自行指定一个能区分不同 Java Web 实例的名称，同一 Tomcat 下所有 webapps 共享该值。消费端据此识别告警/模型报告来自哪个实例（如 `order-service-prod`、`payment-tomcat-01`） |
| `forward.syslog.host` | IP/主机名 | `localhost` | Syslog 服务器地址 |
| `forward.syslog.port` | 1-65535 | `514` | Syslog 服务器 UDP 端口 |

**JVM 系统属性**：
| 参数 | 默认值 | 说明 |
|------|-------|------|
| `rasp.sm.delay` | `15` | SecurityManager 延迟安装秒数（给 Tomcat 预留启动时间） |
| `rasp.sm.immediate` | `false` | 设为 `true` 则立即安装 SecurityManager（非 Tomcat 环境） |

**注意**：
- `block.mode` 默认值为 `monitor`，确保新部署时不会因配置遗漏导致业务中断。
- Agent 参数之间使用**分号**（`;`）分隔，不是逗号。
- 使用 `JAVA_OPTS` 而非 `CATALINA_OPTS` 传递 agent 参数：`CATALINA_OPTS` 会被 `catalina.sh` 通过 `eval` 处理，导致分号被解释为 shell 命令分隔符，参数被截断。

## 5. 工作流程

系统启动后按以下阶段自动运行：

```
JVM 启动
  ↓
安装 RASP SecurityManager (拦截文件 I/O) [延迟 rasp.sm.delay 秒]
  ↓
注册 Bytecode Transformer (拦截动态加载类)
  ├── HttpServlet.service() → 注入 beforeService/afterService 钩子
  └── ServletContext → 注入资源访问检测
  ↓
  基线学习阶段 (默认 5 分钟)
   ├── 学习正常调用栈模式（RASP 内部帧已过滤）
   ├── 构建 CTPG 方法转移图
   ├── beforeService/afterService 过滤: 仅 2xx/3xx 响应计入基线
   ├── 构建 URL 基线: 统计正常请求路径和参数模式
   └── 仅记录学习日志，不告警不阻断
   ↓
  检测阶段
   ├── 实时分析调用栈（过滤 RASP 帧后的业务代码栈）
   ├── 比对基线指纹 (SSF)
   ├── 评估方法转移概率 (CTPG)
   ├── URL 基线比对: 检测新 URL、新参数、频率异常
   ├── isNonSensitiveDefaultServletAccess: HTTP 请求中非敏感文件跳过检测
   ├── analyzeFileSensitivity: 分级评分（+20 ~ +60）
   └── 异常行为告警/阻断
```

## 6. 检测能力

### 6.1 文件操作检测（SecurityManager 层）

| 操作 | 拦截方法 | 覆盖场景 |
|------|---------|---------|
| 文件读取 | `checkRead()` | 冰蝎 `show()`, `download()`, `downloadPart()` |
| 文件写入 | `checkWrite()` | 冰蝎 `upload()`, `updateFile()`, `append()` |
| 文件删除 | `checkDelete()` | 冰蝎 `delete()` |
| 文件创建 | `checkWrite()` (自动覆盖) | 冰蝎 `create()`, `createDirectory()` |
| 命令执行 | `checkExec()` | 冰蝎 `execCommand()` |

### 6.2 动态类 Hook（ASM Transformer 层）

| 类 | 拦截点 | 说明 |
|---|-------|------|
| `javax.servlet.http.HttpServlet` | `service(ServletRequest,ServletResponse)` | HTTP 请求入口，注入 beforeService/afterService 钩子，关联请求上下文，区分扫描器流量 |
| `javax.servlet.ServletContext` | `getRealPath()`, `getResource()`, `getResourceAsStream()` | Web 资源访问检测 |

> 文件 I/O（`java.nio.file.Files`、`java.io.FileInputStream` 等）、反射调用（`java.lang.reflect.Method.invoke()`）、命令执行（`Runtime.exec()`、`ProcessBuilder.start()`）已由 SecurityManager 层统一拦截，无需 ASM 字节码插桩。

### 6.3 敏感目标识别

系统内置分级敏感文件评分系统 (`analyzeFileSensitivity`)，根据风险等级赋予不同分数：

**最高风险 (+60): 系统凭据文件和密钥**
- `/etc/passwd`, `/etc/shadow`, `id_rsa`, `authorized_keys`
- `.keystore`, `.truststore`, `.jks`, `.p12`, `.pfx`

**高风险 (+50): Web 容器核心配置**
- `server.xml`, `web.xml`, `tomcat-users.xml`, `context.xml`
- `catalina.properties`, `catalina.policy`

**中高风险 (+40): 密钥和凭据文件**
- `.key`, `.pem`, `.env`, `.crt`, `.cer`, `private`, `secret`
- `password`, `credential`, `token`

**中风险 (+30): 数据库和中间件配置**
- `application.properties`, `application.yml`, `logback.xml`
- `mysql`, `postgres`, `redis`, `rabbitmq`, `kafka`

**低风险 (+20): config/conf 目录下的配置文件**
- 任何在 `config/` 或 `conf/` 目录下的 `.properties`, `.xml`, `.yml` 文件

**敏感命令评分 (`analyzeCommand`)**:
| 命令类型 | 加分 | 示例 |
|---------|------|------|
| 身份信息获取 | +20 | whoami, id, uname, hostname |
| 网络信息获取 | +15 | ifconfig, ipconfig, netstat, ss, ps |
| 文件浏览 | +10 | ls, cat, dir, type, find, pwd |
| 一般命令 | +5 | date, echo, env, ping |

> 注意：以上字典位于 `TemporalGuard.java` 的 `analyzeFileSensitivity()` 和 `analyzeCommand()` 方法中，可直接修改数组内容自定义。

### 6.4 URL 基线检测 (URL Profile)

系统在学习期内统计所有成功请求（2xx/3xx）的 URL 路径、参数名和参数值最大长度，形成正常访问画像。检测期对偏离基线的行为产生独立告警（`[URL]` 前缀，不与 SSF/CTPG/TTT 评分合并）。

| 告警类型 | 触发条件 | 示例 |
|---------|---------|------|
| `[URL] 新URL首次出现` | 学习期未见过的路径被成功处理 | `/new-endpoint` 首次被请求并返回 200（同一路径仅告警一次） |
| `[URL] 新参数` | 已知路径携带学习期未见的参数名 | `/page?cmd=whoami`（仅 `lang` 在学习基线中） |
| `[URL] 参数值长度超阈值` | 参数值长度超过基线最大长度 × 阈值%（默认 150%） | 学习期 `?q=abcd`（长度 4）→ 检测期 `?q=<3KB_payload>`（长度 3072 > 4×150%） |
| `[URL] 访问频率异常` | 最近 10 次访问速率 > 基线 1.5 倍 | 突发爬虫或 DoS 流量 |

**关键约束**:
- 4xx/5xx 响应不触发 URL 告警 — 扫描器 404 探测（`/wp-admin`、`/.env`）被静默过滤
- 新参数仅对 2xx/3xx 响应检测 — 只有后端实际处理的参数才被检查
- 频率异常内置 30 秒冷却 — 避免同一路径的告警风暴

## 7. 日志与告警

### 7.1 日志文件位置

```
${catalina.base}/
└── stack-anomaly-alerts.log    # 统一告警日志（含初始化、学习进度、检测触发、摘要统计）
```

### 7.2 日志级别说明

| 级别 | 标识 | 默认生产 | 说明 |
|------|------|---------|------|
| DEBUG | `[DEBUG]` | 不写 | 每次操作触发、学习事件等高频日志（需 `debug.log=true`） |
| INFO | `[INFO]` | 不写 | 学习进度、检测触发（需 `verbose.info=true`） |
| WARN | `[WARN]` | 写入 | 初始化、学习完成、每分钟摘要统计 |
| ALARM | `[ALARM]` | 写入 | 异常行为检测命中 |
| BLOCK | `[BLOCK]` | 写入 | 阻断操作触发 |
| ERROR | `[ERROR]` | 写入 | 异常错误 |

### 7.3 日志示例

**学习阶段日志**:

```
[2026-06-15 08:10:00] [INFO] [BaselineLearning] 基线学习开始，学习期: 300000ms
[2026-06-15 08:10:05] [INFO] [BaselineLearning] 学习指纹: -1352098640
[2026-06-15 08:10:05] [INFO] [BaselineLearning] 方法签名数量: 7
[2026-06-15 08:15:00] [INFO] [BaselineLearning] 基线学习完成，进入检测模式
```

**检测阶段告警**:

```
[2026-06-15 08:20:00] [INFO] [TemporalGuard] 文件读取检测触发: /opt/tomcat/conf/server.xml
[2026-06-15 08:20:00] [ALARM] [SensitiveFile] 检测到 Web 容器配置文件：/opt/tomcat/conf/server.xml
[2026-06-15 08:20:00] [ALARM] [TemporalGuard] 中风险时空异常: 分数=35, 文件=/opt/tomcat/conf/server.xml
```

**阻断日志**:

```
[2026-06-15 08:25:00] [BLOCK] [TemporalGuard] 高风险文件读取: 分数=65, 文件=/etc/shadow
[2026-06-15 08:25:00] [ERROR] [TemporalGuard] 调用栈:
    at com.defense.rasp.stackmodel.TemporalGuard.block(TemporalGuard.java:xx)
    at com.defense.rasp.stackmodel.TemporalGuard.onFileRead(TemporalGuard.java:xx)
    at com.defense.rasp.stackmodel.RaspSecurityManager.checkRead(RaspSecurityManager.java:xx)
    at java.io.FileInputStream.<init>(FileInputStream.java:127)
    at net.rebeyond.behinder.payload.java.FileOperation.show(FileOperation.java:42)
```

## 8. 验证与测试

### 8.1 确认 Agent 加载成功

查看 Tomcat 启动日志 (`catalina.out`)，应包含：

```
[StackAnomalyDetector] Agent initialized with args: none
[StackAnomalyDetector] RASP SecurityManager 已安装
[StackAnomalyDetector] Bytecode transformer registered successfully
[StackAnomalyDetector] redefineClasses支持: true
[StackAnomalyDetector] retransformClasses支持: true
[StackAnomalyDetector] 学习引擎初始化完成
```

### 8.2 验证文件读取检测

```bash
# 创建测试文件
echo "测试内容" > /tmp/test-sensitive-file.txt

# 通过 Web 应用尝试读取该文件（模拟冰蝎行为）
curl http://localhost:8080/your-app/api/read?file=/tmp/test-sensitive-file.txt

# 查看日志确认检测触发
tail -f logs/rasp-alerts.log
```

### 8.3 验证告警与阻断

1. **访问敏感文件**: 通过 Webshell 或应用访问 `/etc/passwd`
2. **查看告警**: `tail -f logs/rasp-alerts.log`
3. **确认阻断**: 高风险操作会抛出 `SecurityException`，应用收到异常响应

### 8.4 学习期调整建议

- **开发测试环境**: 设置较短学习期（`learning.duration=60000`）
- **生产环境**: 建议至少 5 分钟（默认值），确保覆盖所有正常业务流

## 9. 故障排查

### 9.1 参数未生效（catalina.sh eval 问题）

**症状**: 启动日志中 `Agent initialized with args` 后面的参数不完整，或部分参数被当作 shell 命令执行。

**原因**: `CATALINA_OPTS` 会被 `catalina.sh` 通过 `eval` 处理，分号被解释为 shell 命令分隔符。

**解决**: 将 `CATALINA_OPTS` 改为 `JAVA_OPTS`（不会被 eval），或直接使用 `java` 命令启动 Tomcat。

### 9.2 Agent 未加载

**症状**: 启动日志中无 `[StackAnomalyDetector]` 相关日志

**排查步骤**:
```bash
# 检查 JAR 路径是否正确
ls -l /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar

# 检查 setenv.sh/sh 配置
cat /path/to/tomcat/bin/setenv.sh

# 查看 Java 进程参数
ps aux | grep javaagent
```

### 9.3 SecurityManager 安装失败

**症状**: 日志中出现 `SecurityManager 安装失败 (权限受限)`

**排查步骤**:
```bash
# 检查是否有安全管理器已安装
ps aux | grep -Djava.security.manager

# 检查 Tomcat 安全策略文件
cat /path/to/tomcat/conf/catalina.policy

# 临时测试：以管理员身份启动 Tomcat
sudo systemctl start tomcat
```

### 9.4 日志文件未生成

**症状**: `logs/` 目录下无 `rasp-*.log` 文件

**排查步骤**:
```bash
# 检查日志目录权限
ls -ld /path/to/tomcat/logs/

# 检查 logback 配置
cat /opt/rasp/logback.xml

# 手动创建日志目录
mkdir -p /path/to/tomcat/logs/
chmod 755 /path/to/tomcat/logs/
```

### 9.5 误报处理

**症状**: 正常业务操作被误报为异常

**解决方案**:
```
1. 延长基线学习期，确保覆盖所有正常业务流程
2. 确认学习期间没有攻击行为混入基线
3. 检查业务代码是否使用了非常规文件访问模式
4. 必要时调整阈值（修改 TemporalGuard.java 中的阈值常量）
```

### 9.6 扫描器噪声与 JSP 编译噪声

**扫描器 404 噪声**：HTTP 扫描器产生的 404 探测请求（如 `/wp-admin`, `/phpmyadmin`）已被系统自动过滤：
- 学习期：`beforeService`/`afterService` 仅学习 2xx/3xx 响应，404/403 不计入基线
- 检测期：`isNonSensitiveDefaultServletAccess` 对 HTTP 请求上下文中 DefaultServlet 访问非敏感文件跳过检测
- 仅安全敏感性路径（`/.env`, `/config/application.properties`, `/WEB-INF/web.xml`）继续告警 — 这是正确行为

**JSP 编译噪声**：Tomcat 首次编译 JSP 时，Jasper 引擎的 JDT 编译器产生大量 `ClassLoader.loadClass` 调用，会被 `checkDangerousClasses` 误报。解决方式：学习期内预编译所有 JSP 页面。参见 `stack-anomaly-detector-deployment-guide.md` 的策略 C。

### 9.7 敏感文件检测精度

系统使用分级评分 (`analyzeFileSensitivity`) 代替简单布尔值：
- 不同敏感级别的文件获得不同加分（+20 ~ +60）
- 确保高敏感文件（如 `/etc/passwd` +60）即使在基线中有部分匹配也能达到告警阈值
- 普通敏感文件（如通用 `.properties` 文件 +20）不会单独触发告警，需配合 SSF/CTPG 异常

## 10. 升级与回滚

### 10.1 升级步骤

```bash
# 1. 停止 Tomcat
systemctl stop tomcat

# 2. 备份旧版本
cp /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar.bak

# 3. 替换新版本
cp new-version.jar /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar

# 4. 启动 Tomcat
systemctl start tomcat

# 5. 验证升级
tail -f logs/catalina.out | grep StackAnomalyDetector
```

### 10.2 回滚步骤

```bash
# 1. 停止 Tomcat
systemctl stop tomcat

# 2. 移除 Agent 参数（编辑 setenv.sh）
# 删除或注释掉包含 -javaagent 的行

# 3. 启动 Tomcat
systemctl start tomcat

# 或直接恢复备份版本
cp /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar.bak /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar
```

## 11. 安全注意事项

1. **SecurityManager 兼容性**: 如果目标应用已安装 SecurityManager，RASP 会自动连接为父级管理器，不会覆盖现有安全策略
2. **日志保护**: 建议将 `rasp-*.log` 文件权限设置为 `600`，仅限管理员读取
3. **JAR 完整性**: 建议对 JAR 文件进行签名，部署前校验 SHA256
4. **学习期防护**: 基线学习期间系统只记录不阻断，学习期应确保环境安全

## 12. 常见问题 (FAQ)

**Q: 是否支持 Java 11+？**
A: 当前版本针对 Java 8 构建，Java 11+ 需要重新编译并调整 SecurityManager 相关代码（Java 11 中 SecurityManager 已标记为废弃）。

**Q: 是否会影响应用性能？**
A: 基线学习期间有轻微开销（调用栈采集），检测阶段仅在触发检测点时计算，对正常业务影响小于 3%。

**Q: 如何调整风险阈值？**
A: 修改 `TemporalGuard.java` 中的 `HIGH_RISK_THRESHOLD` (默认 50) 和 `MEDIUM_RISK_THRESHOLD` (默认 20) 常量，重新编译部署。

**Q: 检测规则是否可以自定义？**
A: 敏感文件评分字典位于 `TemporalGuard.java` 的 `analyzeFileSensitivity()` 方法，敏感命令字典位于 `analyzeCommand()` 方法，可直接修改数组内容和分值。危险类列表位于 `BaselineLearningEngine.java` 的 `checkDangerousClasses()` 方法。

**Q: 如何避免误报阻断正常业务？**
A: 系统默认使用 `block.mode=monitor`（仅告警），不会阻断任何请求。部署首周建议保持此模式，通过告警日志观察业务行为。确认无误报后，再切换为 `block.mode=block`。

**Q: 学习期被攻击怎么办？**
A: 学习期间所有行为仅记录基线，不进行异常检测，因此学习期内的攻击行为不会被识别为异常。确保学习期间应用处于安全环境。

**Q: 扫描器 404 探测会产生误报吗？**
A: 不会。系统实现双层保护：(1) 学习期仅学习 2xx/3xx 响应，404 不计入基线；(2) 检测期 `isNonSensitiveDefaultServletAccess` 对 HTTP 请求上下文中 DefaultServlet 访问非敏感文件跳过检测。通用 404 路径（如 wp-admin, phpmyadmin, backup）已被验证为零误报。仅安全敏感路径（如 `/.env`, `/config/application.properties`）会继续告警 — 这是正确行为。

**Q: 为什么 CTPG 告警不再显示 RASP 自身的方法转移？**
A: `StackFingerprint` 在构建时自动过滤 `com.defense.rasp.*` 和 `Thread.getStackTrace` 帧，CTPG 只追踪业务代码和攻击代码的转移关系。详见 `detection-model-and-principles.md` 的 2.3 和 3.2 节。

**Q: JSP 首次访问产生大量告警怎么办？**
A: 在学习期内预编译所有 JSP。Tomcat 的 JDT 编译器类加载在学习期不产生告警。详见 `stack-anomaly-detector-deployment-guide.md` 的策略 C。

**Q: URL 基线告警「新URL首次出现」是什么含义？**
A: 学习期未访问过的路径在检测期首次被请求并返回 2xx/3xx 时触发。同一路径仅告警一次，后续访问不再重复记录，避免日志刷屏。若为正常业务页面遗漏，需延长学习期重新部署。扫描器 404 探测（如 /wp-admin）不会触发此告警。

**Q: 新参数告警是否会被扫描器触发？**
A: 不会。新参数检测仅在响应为 2xx/3xx 时生效，即参数必须被后端实际处理。扫描器对任意路径的 `?id=1' OR '1'='1` 探测若返回 404 不告警。

**Q: 如何查看学习到的 URL 基线？**
A: 学习完成后生成的 `stack-anomaly-baseline-report.log` 包含「URL 基线」章节，列出所有学习到的路径、访问频次、参数名和参数值最大长度。也可通过告警日志中的 `[URL] URL基线学习完成` 行查看统计。

**Q: 频率异常告警会产生告警风暴吗？**
A: 不会。频率异常内置 30 秒冷却，同一路径每分钟最多产生 2 条告警。基线速率基于学习期访问次数计算，仅在当前速率超过基线 1.5 倍时触发（可通过 `url.freq.threshold` 启动参数或管理控制台调节）。

**Q: 参数值长度超阈值告警是什么？**
A: 学习期记录每个参数值的最大长度。检测期若某参数值的实际长度超过学习期最大长度的 150%（默认），触发 `[URL] 参数值长度超阈值` 告警。例如学习期 `?q=abcd`（长度 4），检测期 `?q=<3KB_payload>`（长度 3072 > 4×150%=6）触发告警。阈值可通过 `url.param.threshold` 启动参数或管理控制台在线调节。

**Q: 如何在线调整 URL 基线阈值？**
A: 访问模型管理控制台 `http://host:port/examples/model-console.jsp`，在 URL 标签页顶部的表单中直接修改频率阈值和参数值长度阈值，提交后即时生效，无需重启。

## 13. 推荐部署流程

```
第 1 周：监控观察期
  配置: block.mode=monitor (默认)
  目标: 收集正常业务调用栈基线，观察告警日志

第 2 周：验证期
  操作: 分析 rasp-alerts.log 中的告警，确认是否为真实攻击
  如果无误报: 进入第 3 周

第 3 周起：阻断期
  配置: block.mode=block
  监控: 关注 rasp-blocks.log，确认被阻断的请求均为攻击行为
```

---

## 14. 模型管理控制台 (Model Management Console)

学习阶段完成后，可通过内置 JSP 管理控制台可视化查看和微调所有检测模型。

### 14.1 部署

```bash
cp model-console.jsp $CATALINA_BASE/webapps/examples/model-console.jsp
```

建议在学习期预编译（提前访问一次），避免检测期触发 JDT 类加载告警。

### 14.2 核心功能

| 标签页 | 操作 | 用途 |
|--------|------|------|
| SSF 调用栈指纹 | 查看学习到的所有调用栈指纹（按深度排序），可展开完整调用链 | 审计正常行为签名 |
| SSF 指纹管理 | 移除特定指纹（如误学习的开发/测试路径） | 微调检测灵敏度 |
| CTPG 管控转移概率图 | 查看所有方法转移关系及概率 | 审计正常调用路径 |
| CTPG 转移管理 | 移除低概率或异常的转移关系 | 降低误报 |
| URL Profile | 查看学习到的 URL 路径、访问频率和参数名集合 | 审计正常 URL 模式 |
| URL 路径管理 | 移除特定 URL 路径 | 调整 URL 覆盖范围 |
| 操作区 | 重新学习、强制结束学习 | 动态切换学习/检测模式 |

### 14.3 使用场景

| 场景 | 操作 |
|------|------|
| 学习到测试/开发路径的指纹，产生误报 | 移除该 SSF 指纹 → 下次访问该路径触发 SSF 未知告警 |
| 某 URL 路径在后端实际有参数注入风险，不应被基线豁免 | 移除该 URL 路径 → 后续访问触发新 URL 告警 |
| 业务更新引入新接口，需要更新基线 | 点击"重新学习" → 清空基线重新采集 |
| 学习期意外延长或需立即切换检测 | 点击"强制结束学习" |

### 14.4 生效机制

所有修改操作在同一个 JVM 进程中执行，直接操作内存中的并发数据结构（`ConcurrentHashMap`），修改后下次请求立即生效，无需重启。

### 14.5 安全建议

- JSP 无内置认证，生产环境建议仅内部可访问或通过 Tomcat `security-constraint` 配置 BASIC 认证
- 修改操作记录在 `stack-anomaly-alerts.log` 中，关键字 `[ModelMgmt]`
- 误移除的项可通过"重新学习"恢复

---

## 15. 告警与模型结果外发 (Forwarding)

### 15.1 概述

支持将告警日志和模型学习结果通过 Syslog 或 Kafka 外发至第三方日志服务器（SIEM、RASP Server 等），便于集中管理和分析。

### 15.2 消息格式

外发消息为 JSON 格式，包含统一头部：

```json
{
  "type": "alert | model",
  "app": "应用实例标识",
  "timestamp": "Unix毫秒时间戳"
}
```

**告警消息**（`type=alert`）：
- `level`: ALARM / BLOCK / WARN
- `prefix`: 告警前缀（如 `[URL]`、`[CTPG]`、`[DangerousClass]`）
- `message`: 完整告警内容

**模型报告**（`type=model`）：
- `ssf_count`: SSF 指纹数量
- `ctpg_size`: CTPG 转移图节点数
- `url_path_count`: URL 基线路径数
- `url_total_requests`: URL 学习期总请求数
- `ssf_fingerprints`: 指纹 JSON 数组
- `ctpg_transitions`: 转移 JSON 数组
- `url_paths`: URL 路径 JSON 数组

### 15.3 使用示例

```bash
# Syslog 转发
-javaagent:rasp.jar=forward.type=syslog,forward.app.name=order-service,forward.syslog.host=192.168.1.100,forward.syslog.port=514

# 多实例部署（同一服务器）
# 实例1: order-service
-javaagent:rasp.jar=forward.type=syslog,forward.app.name=order-service,...

# 实例2: payment-service
-javaagent:rasp.jar=forward.type=syslog,forward.app.name=payment-service,...
```

### 15.4 发送时机

- **告警**：产生后立即外发（ALARM / BLOCK / WARN 级别）
- **模型报告**：每次学习完成后外发一次；重新学习后再次触发

### 15.5 测试验证

项目内置最小化 Syslog 接收器 `tools/syslog-receiver.py`，部署前可在测试环境验证外发功能。

```bash
# 步骤1: 启动 Syslog 接收器（终端1）
python3 tools/syslog-receiver.py 514

# 步骤2: 启动 Tomcat 并配置转发参数（终端2）
export CATALINA_OPTS="-javaagent:/opt/tomcat85/stack-anomaly-detector.jar=forward.type=syslog,forward.app.name=my-test-app,forward.syslog.host=127.0.0.1,forward.syslog.port=514,debug.log=true"
/opt/tomcat85/bin/catalina.sh run

# 步骤3: 访问任意 URL 触发告警
curl http://localhost:8080/examples/

# 预期: 接收器终端输出
#   [10:30:15] my-test-app [URL] 新URL首次出现: /examples
#   [10:30:45] my-test-app MODEL: SSF=15 CTPG=83 URL=2
```

---

**版本**: 1.1.0  
**更新日期**: 2026-07-06  
**构建**: `mvn clean package`
