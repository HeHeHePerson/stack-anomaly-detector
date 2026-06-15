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
CATALINA_OPTS="$CATALINA_OPTS -javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar"
```

**Windows (setenv.bat)**:

```bat
set CATALINA_OPTS=%CATALINA_OPTS% -javaagent:C:\opt\rasp\stack-anomaly-detector-1.0.0-shaded.jar
```

### 4.2 Spring Boot 部署方式

```bash
java -javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar \
     -jar your-application.jar
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
-javaagent:/opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar=block.mode=monitor,learning.duration=600000
```

完整参数表：
| 参数 | 可选值 | 默认值 | 说明 |
|------|--------|--------|------|
| `block.mode` | `monitor`, `block` | `monitor` | 检测到高风险行为时是否阻断（`monitor`=仅告警不阻断） |
| `learning.duration` | 正整数（毫秒） | `300000` | 基线学习时长，此期间所有操作仅记录不告警 |

**注意**：`block.mode` 默认值为 `monitor`，确保新部署时不会因配置遗漏导致业务中断。

## 5. 工作流程

系统启动后按以下阶段自动运行：

```
JVM 启动
  ↓
安装 RASP SecurityManager (拦截文件 I/O)
  ↓
注册 Bytecode Transformer (拦截动态加载类)
  ↓
基线学习阶段 (默认 5 分钟)
  ├── 学习正常调用栈模式
  ├── 构建线程轨迹图 (TTT)
  └── 仅记录日志，不阻断
  ↓
检测阶段
  ├── 实时分析调用栈
  ├── 比对基线指纹
  ├── 检测敏感文件/目录
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

### 6.2 动态类 Hook（ASM Transformer 层）

| 类 | 拦截点 | 说明 |
|---|-------|------|
| `javax.servlet.http.HttpServlet` | `service()` | HTTP 请求入口，关联请求上下文 |
| `javax.servlet.ServletContext` | `getRealPath()`, `getResource()` | Web 资源访问检测 |
| `java.nio.file.Files` | `readAllBytes()`, `write()`, `delete()` | NIO 文件操作 |
| `java.lang.reflect.Method` | `invoke()` | 反射调用检测 |
| `java.lang.Runtime` | `exec()` | 命令执行检测 |
| `java.lang.ProcessBuilder` | `start()` | 进程创建检测 |
| `java.io.FileDescriptor` | `open()` | 底层 I/O 操作（当动态加载时） |

### 6.3 敏感目标识别

系统内置敏感文件和目录字典，覆盖以下类型：

**敏感文件**:
- Web 容器配置：`server.xml`, `web.xml`, `tomcat-users.xml`, `context.xml`
- 应用配置：`application.yml`, `logback.xml`, `jdbc.properties`
- 密钥凭据：`.keystore`, `.p12`, `id_rsa`, `authorized_keys`
- 系统文件：`/etc/passwd`, `/etc/shadow`, `.env`
- 数据库配置：包含 `mysql`, `redis`, `rabbitmq` 等关键词的配置文件

**敏感目录**:
- Tomcat 目录：`tomcat/conf`, `tomcat/webapps`, `tomcat/logs`
- 系统目录：`/etc/`, `Windows/System32`
- 版本控制：`.git/`, `.svn/`
- 应用目录：`WEB-INF/`, `META-INF/`, `config/`, `secrets/`

## 7. 日志与告警

### 7.1 日志文件位置

```
${catalina.base}/logs/
├── rasp-agent.log      # Agent 运行日志
├── rasp-alerts.log     # 告警日志 (ALARM)
└── rasp-blocks.log     # 阻断日志 (BLOCK)
```

### 7.2 日志级别说明

| 级别 | 标识 | 说明 |
|------|------|------|
| INFO | `[INFO]` | 系统状态、学习进度、检测触发 |
| ALARM | `[ALARM]` | 检测到异常行为，记录告警 |
| BLOCK | `[BLOCK]` | 达到阻断阈值，操作被拦截 |

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

### 9.1 Agent 未加载

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

### 9.2 SecurityManager 安装失败

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

### 9.3 日志文件未生成

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

### 9.4 误报处理

**症状**: 正常业务操作被误报为异常

**解决方案**:
```
1. 延长基线学习期，确保覆盖所有正常业务流程
2. 确认学习期间没有攻击行为混入基线
3. 检查业务代码是否使用了非常规文件访问模式
4. 必要时调整阈值（修改 TemporalGuard.java 中的阈值常量）
```

## 10. 升级与回滚

### 10.1 升级步骤

```bash
# 1. 停止 Tomcat
systemctl stop tomcat

# 2. 备份旧版本
cp /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar \
   /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar.bak

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
cp /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar.bak \
   /opt/rasp/stack-anomaly-detector-1.0.0-shaded.jar
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
A: 修改 `TemporalGuard.java` 中的 `HIGH_RISK_THRESHOLD` 和 `MEDIUM_RISK_THRESHOLD` 常量，重新编译部署。

**Q: 检测规则是否可以自定义？**
A: 敏感文件和目录字典位于 `TemporalGuard.java` 的 `isSensitiveFile()` 和 `isSensitiveDirectory()` 方法中，可直接修改数组内容。

**Q: 如何避免误报阻断正常业务？**
A: 系统默认使用 `block.mode=monitor`（仅告警），不会阻断任何请求。部署首周建议保持此模式，通过告警日志观察业务行为。确认无误报后，再切换为 `block.mode=block`。

**Q: 学习期被攻击怎么办？**
A: 学习期间所有行为仅记录基线，不进行异常检测，因此学习期内的攻击行为不会被识别为异常。确保学习期间应用处于安全环境。

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

**版本**: 1.0.0  
**更新日期**: 2026-06-15  
**构建**: `mvn clean package`
