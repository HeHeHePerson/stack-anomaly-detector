# Stack Anomaly Detector 检测模型与技术原理

## 1. 系统架构

```
┌─────────────────────────────────────────────────────────┐
│                   Java Agent (premain)                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────────────┐  ┌──────────────────────────┐ │
│  │ RaspSecurityManager  │  │ TemporalStackTransformer │ │
│  │ (文件/命令拦截层)     │  │ (字节码 Hook 层)         │ │
│  │                      │  │                          │ │
│  │ checkRead/Write/     │  │ HttpServlet.service()    │ │
│  │ Delete/Exec          │  │ ServletContext.*         │ │
│  └─────────┬────────────┘  └────────────┬─────────────┘ │
│            │                            │                │
│            └──────────┬─────────────────┘                │
│                       ▼                                  │
│  ┌─────────────────────────────────────────────────────┐│
│  │                 TemporalGuard                        ││
│  │              (统一检测编排入口)                        ││
│  │  onFileRead / onFileWrite / onFileDelete             ││
│  │  onCommandExec / onHttpServlet / onReflectInvoke     ││
│  └─────────┬───────────────────────────────────────────┘│
│            │                                            │
│            ▼                                            │
│  ┌─────────────────────────────────────────────────────┐│
│  │           BaselineLearningEngine                     ││
│  │              (时空异常检测核心)                        ││
│  │  learnNormalStack() / detectAnomaly()                ││
│  └─────────┬───────────────────────────────────────────┘│
│            │                                            │
│            ▼                                            │
│  ┌─────────────────────────────────────────────────────┐│
│  │            StackTemporalEngine                       ││
│  │         (四种时空模型数据结构)                         ││
│  │  SSF ── CTPG ── TTT ── URL Profile                  ││
│  └─────────────────────────────────────────────────────┘│
│                                                         │
│  ┌─────────────────────────────────────────────────────┐│
│  │       Model Management Console (model-console.jsp)   ││
│  │     (Web 管理控制台：模型可视化 + 微调 + 重学)         ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            ││
│  │  │ SSF 查询 │ │ CTPG 查询│ │URL Profile│            ││
│  │  │ 与移除   │ │ 与移除   │ │ 与移除   │            ││
│  │  └──────────┘ └──────────┘ └──────────┘            ││
│  │  ┌──────────────────────────────────┐              ││
│  │  │ 重新学习 / 强制结束学习           │              ││
│  │  └──────────────────────────────────┘              ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

## 2. 数据采集层

### 2.1 SecurityManager 拦截（文件与命令操作）

`RaspSecurityManager` 继承 `java.lang.SecurityManager`，重写以下方法拦截所有文件 I/O 和进程执行：

| 重写方法 | 触发时机 | 转发目标 |
|---------|---------|---------|
| `checkRead(String)` | 任何文件读取 | `TemporalGuard.onFileRead()` |
| `checkWrite(String)` | 任何文件写入 | `TemporalGuard.onFileWrite()` |
| `checkDelete(String)` | 任何文件删除 | `TemporalGuard.onFileDelete()` |
| `checkExec(String)` | 任何命令执行 | `TemporalGuard.onCommandExec()` |

**防重入机制**：`ThreadLocal<Boolean> IN_DETECTION` 标记防止检测逻辑内部的日志写入再次触发 `checkWrite` 导致 `StackOverflowError`。

```java
// 核心模式：每个 check 方法遵循三明治结构
public void checkRead(String file) {
    if (IN_DETECTION.get()) return;     // 防重入
    try {
        IN_DETECTION.set(true);          // 标记检测中
        TemporalGuard.onFileRead(file);  // 执行检测
    } catch (Throwable e) {
        // 静默吞下所有异常，绝不中断业务
    } finally {
        IN_DETECTION.remove();           // 清除标记
    }
}
```

### 2.2 ASM 字节码 Hook（HTTP 请求入口）

`TemporalStackTransformer` 使用 ASM 对 `javax.servlet.http.HttpServlet.service()` 注入检测调用：

```
原始字节码:
  public void service(ServletRequest req, ServletResponse resp) {
      ... // Tomcat 原始逻辑
  }

注入后:
  public void service(ServletRequest req, ServletResponse resp) {
      TemporalGuard.onHttpServlet(req);  // ← 注入点
      ... // Tomcat 原始逻辑
  }
```

**为什么不 Hook Bootstrap 类？**  `java.io.*`、`java.nio.*`、`java.lang.*` 由 Bootstrap ClassLoader 加载，早于 Agent 附着。注入的字节码引用了 `TemporalGuard` 类，但该类在 Agent JAR 中，Bootstrap ClassLoader 无法访问，导致 `NoClassDefFoundError`。因此文件 I/O 拦截完全交由 SecurityManager。

### 2.3 调用栈采集与帧过滤

每次检测触发时，通过 `Thread.currentThread().getStackTrace()` 获取完整调用栈，然后由 `StackFingerprint.extractMethodSignatures()`  过滤噪声帧：

**自动过滤的帧**：
- `com.defense.rasp.*` — RASP 内部检测链（TemporalGuard、RaspSecurityManager、BaselineLearningEngine），避免 CTPG 显示自身转移
- `java.lang.Thread.getStackTrace` — 栈采集自身的帧，永远位于栈顶

**过滤前**：
```
  java.lang.Thread.getStackTrace                              ← 过滤
  com.defense.rasp.stackmodel.TemporalGuard.onFileRead        ← 过滤 (RASP)
  com.defense.rasp.stackmodel.RaspSecurityManager.checkRead   ← 过滤 (RASP)
  java.lang.SecurityManager.checkRead                         ← 保留
  java.io.FileInputStream.<init>                              ← 保留
  org.apache.catalina.servlets.DefaultServlet.serveResource   ← 保留
  org.apache.catalina.servlets.DefaultServlet.doGet           ← 保留
  javax.servlet.http.HttpServlet.service                      ← 保留
  ...
```

**过滤后** (CTPG / SSF 使用此版本)：
```
  java.lang.SecurityManager.checkRead
  java.io.FileInputStream.<init>
  org.apache.catalina.servlets.DefaultServlet.serveResource
  org.apache.catalina.servlets.DefaultServlet.doGet
  javax.servlet.http.HttpServlet.service
  ...
```

> CTPG 转移对从 `SecurityManager → FileInputStream` 开始，不再包含 `TemporalGuard → RaspSecurityManager` 等 RASP 自身转移。冰蝎命令执行的调用链中，`Runtime.exec → ProcessBuilder` 等真实攻击转移才能暴露。

## 3. 三种时空检测模型

### 3.1 SSF —— 调用栈签名指纹 (Stack Signature Fingerprint)

**数据结构**：

```java
class StackFingerprint {
    int fingerprintHash;           // 方法签名串 hashCode
    List<String> methodSignatures; // 逐帧方法签名列表（已过滤 RASP + Thread 帧）
}
```

**构建过程**：
1. 从 `StackTraceElement[]` 提取每帧的 `ClassName.MethodName`
2. 过滤 `com.defense.rasp.*` 和 `Thread.getStackTrace` 帧
3. 拼接剩余帧为 `"A.b|C.d|E.f|..."` 字符串
4. 对拼接串取 `hashCode()` 作为指纹

**异常判定**：
- 指纹哈希不在启动期指纹库 `NORMAL_STARTUP_FINGERPRINTS` 中
- 且不在运行期指纹库 `NORMAL_RUNTIME_FINGERPRINTS` 中
- → **+30 分**

**相似度补偿**：当指纹未知时，使用 LCS（最长公共子序列）算法计算当前调用栈与所有已知指纹的相似度。若最大相似度 < 0.3，额外 **+20 分**。

```
已知指纹: [A, B, C, D, E, F]
当前栈:  [A, B, X, D, E, F]
LCS:     [A, B, D, E, F] → 长度 5
相似度 = 5 / max(6, 6) = 0.833 → 不触发 +20
```

### 3.2 CTPG —— 调用转移概率图 (Context-aware Transition Probability Graph)

**数据结构**：

```java
// TRANSITION_GRAPH: ConcurrentHashMap<String, TransitionNode>
// key = 源方法签名, value = 转移节点

class TransitionNode {
    String sourceMethod;
    ConcurrentHashMap<String, Long> targetCounts; // 目标方法 → 转移次数
    long totalTransitions;
}

// 概率计算
double getProbability(String target) {
    return targetCounts.get(target) / totalTransitions;
}
```

**构建过程**：遍历调用栈（已过滤 RASP 帧）的相邻帧对 `(frame[i], frame[i+1])`，记录转移次数。

```
调用栈: [Z, Y, X, W, V]  (已过滤 RASP 帧)
转移对: Z→Y, Y→X, X→W, W→V

TRANSITION_GRAPH:
  "Z" → {Y: 5次, ...}  概率(Z→Y) = 0.3
  "Y" → {X: 8次, ...}  概率(Y→X) = 0.8
  "X" → {W: 9次, ...}  概率(X→W) = 0.7
  "W" → {V: 3次, ...}  概率(W→V) = 0.2
```

**帧过滤对 CTPG 的关键影响**：

过滤前（含 RASP 帧）的转移对：
```
Thread.getStackTrace → TemporalGuard.onCommandExec     ← RASP 自身
TemporalGuard.onCommandExec → RaspSecurityManager.checkExec  ← 冰蝎不可见
SecurityManager.checkExec → Runtime.exec                    ← 真实攻击
Runtime.exec → ProcessBuilder.start                          ← 真实攻击
```

过滤后的转移对（冰蝎可见）：
```
SecurityManager.checkExec → Runtime.exec              ← CTPG 告警起点
Runtime.exec → ProcessBuilder.start                    ← 异常转移
ProcessBuilder.start → (冰蝎调用链)                     ← 攻击路径
```

> 没有帧过滤时，告警始终显示 `TemporalGuard.onCommandExec → RaspSecurityManager.checkExec (未知源)`，用户看不到冰蝎相关方法。过滤后，告警展示真实攻击链中的未知转移。

**异常判定**：

| 条件 | 分数 |
|------|------|
| 某对转移的源方法在图中不存在（从未出现过） | **+35** |
| 转移概率 < 0.01 (`MIN_NORMAL_PROBABILITY`) | **+35** |
| 转移概率 < 0.1 | **+15** |

**扫描器噪声过滤 (isNonSensitiveDefaultServletAccess)**：

HTTP 扫描器发送 404 探测时，Tomcat `DefaultServlet` 仍会通过 `CachedResource.validateResource` 触发 `checkRead`。若该路径已在学习期见过，CTPG 不会告警；若未见过，则展示 `DefaultServlet` 内部转移。

为防止 HTTP 请求上下文中非敏感文件的 `DefaultServlet` 访问触发 CTPG 误报，`TemporalGuard` 实现了 `isNonSensitiveDefaultServletAccess` 过滤器：

```
条件（三者同时满足时跳过检测）:
  1. PENDING_REQUEST_URI != null       (HTTP 请求上下文)
  2. 栈中存在 DefaultServlet 或 JspServlet
  3. analyzeFileSensitivity(filePath) == 0  (非敏感文件)
```

> 这意味着：扫描器探测 `.env` 时，即使通过 DefaultServlet，因 `analyzeFileSensitivity` 返回 +40 > 0，检测正常执行。探测 `/nonexistent` 时，返回 0，检测跳过 — 通用扫描器零误报。

**Behinder 攻击的 CTPG 特征**：正常 Tomcat 请求的调用链为 `DefaultServlet → CachedResource → File.canRead`。Behinder 的链为 `BehinderFilter → FileInputStream → Runtime.exec`。后者包含大量图中不存在的转移边，且不被 `isNonSensitiveDefaultServletAccess` 跳过（访问的是敏感文件如 `/etc/passwd`）。

### 3.3 TTT —— 线程时序轨迹 (Thread Temporal Trajectory)

**数据结构**：

```java
class ThreadTrajectory {
    long threadId;
    String threadName;
    CopyOnWriteArrayList<CallEvent> events; // 调用事件序列
}

class CallEvent {
    long timestamp;
    String methodSignature;
    EventType type; // ENTER 或 EXIT
}
```

**检测模式**：

| 模式 | 描述 | 分数 |
|------|------|------|
| `SUSPICIOUS_TRANSITION` | 反射调用后紧跟文件 I/O | **+20** |
| `SUSPICIOUS_TRANSITION` | ClassLoader 后紧跟 defineClass | **+20** |
| `WEB_TO_IO_DIRECT` | Web 入口直接触达 IO，无业务中间层 | **+20** |
| `SHALLOW_CALL_DEPTH` | Web 入口到 IO 的调用深度 < 3 | **+20** |
| `DEEP_REFLECTION` | 反射嵌套深度 > 3 层 | **+20** |

**Web→IO 直连检测逻辑**：

```java
// 方法分类标签
tagMethod(sig) → {
    "org.apache.catalina" → "tomcat-core"
    "javax.servlet"       → "servlet-api"
    "java.lang.reflect"   → "java-reflect"
    "java.io"             → "java-io"
    "java.nio"            → "java-nio"
    "org.springframework" → "spring-core"
    default               → "user-code"
}

// 异常条件：有 Web 入口 + 有 IO 操作 + 无业务层
if (hasWebEntry && !hasBusinessLayer && hasIO) → +20
```

这意味着如果一个请求的处理线程在其轨迹中同时出现了 `tomcat-core` 和 `java-io` 标记，但缺少 `spring-core` 或 `user-code` 标记，即可疑。Behinder 的 `Equals` 页面路径穿越操作正是这种模式——请求直接进入 Behinder Filter，然后跳过业务层直接执行文件 IO。

### 3.4 URL Profile —— URL 基线统计 (URL Baseline Profile)

**核心理念**：在学习期内统计所有成功请求（2xx/3xx）的 URL 路径和参数模式，形成正常访问画像。检测期对偏离基线的请求（新 URL、新参数、频率异常）产生告警。

**数据结构**：

```java
class UrlBaseline {
    String path;                      // 归一化路径（去查询串、去末尾斜杠）
    AtomicLong totalVisits;           // 学习期内总访问次数
    Set<String> paramKeys;            // 学习期内该路径出现的所有参数名
    long learningDurationMs;          // 学习时长，用于计算基准速率
}

// BASELINE: ConcurrentHashMap<String(path), UrlBaseline>
// RECENT_TIMESTAMPS: ConcurrentHashMap<String(path), long[10]> 滑动窗口
```

**学习阶段**（`afterService` 中，仅 2xx/3xx 响应）：

```
1. 从 PENDING_REQUEST_URI 获取完整 URI（含 query string）
2. 归一化路径：剥离 query string、移除末尾斜杠
3. 记录或更新 UrlBaseline：
   - path 首次出现 → 新建条目
   - totalVisits +1
   - 提取 query string 中的参数名 → 加入 paramKeys
4. 仅成功响应 (2xx/3xx) 被学习，与 SSF/CTPG 的扫描器过滤策略一致
```

**检测阶段**（`afterService` 中，所有响应）：

| 规则 | 触发条件 | 评分 | 说明 |
|------|---------|------|------|
| 新 URL | path 不在 BASELINE 中，且响应为 2xx/3xx | 告警 | 学习期从未出现的路径被后端成功处理 |
| 新参数 | path 在 BASELINE 中，但 query string 含未知参数名 | 告警 | 可能为攻击参数注入（如 ?cmd=whoami） |
| 频率异常 | 最近 10 次访问速率 > 基线速率 5 倍 | 告警（30s 冷却） | 防止扫描器或 DoS 类型的突发流量 |

**关键设计约束**：
- 4xx/5xx 响应不触发任何 URL 告警 — 无目的性扫描产生的 404 不产生噪声
- 新参数检测仅对成功响应（2xx/3xx）生效 — 确保参数被后端实际处理
- 频率异常内置 30 秒冷却 — 同一路径每分钟最多告警 2 次
- URL 基线告警独立于 SSF/CTPG/TTT 评分体系，通过 `[URL]` 前缀告警日志区分

**`beforeService` 的 query string 捕获**：

```java
// HttpServletRequest.getRequestURI() 不包含 query string
// 必须额外调用 getQueryString() 拼接
String uri = (String) req.getClass().getMethod("getRequestURI").invoke(req);
String query = (String) req.getClass().getMethod("getQueryString").invoke(req);
if (query != null && !query.isEmpty()) {
    uri = uri + "?" + query;
}
PENDING_REQUEST_URI.set(uri);
```

**检测示例**：

```
学习期访问: /examples/index.html?lang=zh → 基线: path=/examples/index.html, params=[lang]

检测期:
  /examples/index.html              → 已知路径，无参数 → 静默
  /examples/index.html?lang=en      → 已知路径，已知参数 → 静默
  /examples/index.html?cmd=whoami   → 已知路径，新参数 cmd → [URL] 新参数告警
  /examples/jsp/num/numguess.jsp    → 新路径 → [URL] 新URL首次出现告警
  /wp-admin (404)                   → 4xx 响应，不告警
```

**基线报告输出**：

```
--- URL 基线 (URL Profile) ---
总路径数: 7
总请求数: 7
(按访问次数降序)

  [  1] /examples                        访问=1次 (2.0/min)  参数=[]
  [  2] /examples/servlets               访问=1次 (2.0/min)  参数=[]
  [  3] /examples/index.html             访问=1次 (2.0/min)  参数=[lang]
  ...
```

## 4. 学习引擎

### 4.1 两阶段模型

```
启动期 (0~120s)                运行期 (120s~300s)             检测期 (>300s)
───────────────── ─────────────────────────────── ─────────────────────────
存入 STARTUP_FINGERPRINTS       存入 RUNTIME_FINGERPRINTS        learnNormalStack() 跳过
CTPG 建立转移边                  CTPG 继续建立转移边              detectAnomaly() 评分
所有操作分数=0                 所有操作分数=0                   按规则评分
```

### 4.2 学习内容

每次调用 `learnNormalStack(stack, isStartup)` 执行三项操作，`afterService` 额外执行 URL 基线学习：

| 操作 | 存储位置 | 用途 |
|------|---------|------|
| 注册指纹哈希 | `NORMAL_STARTUP_FINGERPRINTS` 或 `NORMAL_RUNTIME_FINGERPRINTS` | SSF 匹配 |
| 存储完整指纹对象 | `FINGERPRINT_OBJECTS` | LCS 相似度计算 |
| 建立转移边 | `TRANSITION_GRAPH` (CTPG) | 转移概率评估 |
| 记录 URL 路径与参数 | `UrlBaselineModel.BASELINE` | URL 基线比对 |

### 4.3 学习期结束

后台守护线程每 30 秒检查一次，当 `elapsed > LEARNING_DURATION_MS` 时：
1. 设置 `isLearningPhase = false`
2. 调用 `UrlBaselineModel.finishLearning()` 关闭 URL 基线学习
3. 记录学习统计（指纹数量、转移图大小、URL 基线路径数）
4. 若 `baseline.report=true`（默认），生成 `stack-anomaly-baseline-report.log`（含 SSF、CTPG、URL Profile 三个章节）
5. 后续所有 `detectAnomaly()` 和 `UrlBaselineModel.checkUrl()` 调用进入实际检测模式

## 5. 评分与决策

### 5.1 评分公式

**SSF/CTPG/TTT 综合评分**（`detectAnomaly` 内部，上限 100）：

```
总分 = min(
    SSF指纹未知(+30)
  + SSF相似度过低(+20)
  + CTPG转移未知或概率<0.01(+35)
  + CTPG转移偏低<0.1(+15)
  + TTT轨迹异常(+20 × N条)
  + checkSensitiveFileAccess: 敏感文件访问(+30)
  + checkDangerousClasses: 危险类调用(+20 × N类)
  + hasReflection && hasFileIO(+30)
  , 100)
+
TemporalGuard 层追加:
  + analyzeFileSensitivity(filePath)  分级: +20/+30/+40/+50/+60
  + analyzeCommand(command)           分级: whoami=+20, ifconfig=+15, ls=+10, date=+5
```

**URL 基线独立评分**（`UrlBaselineModel.checkUrl`，不参与 SSF/CTPG/TTT 分数累计）：

| 规则 | 触发方式 | 告警前缀 |
|------|---------|---------|
| 新 URL | 2xx/3xx 路径不在 BASELINE 中 | `[URL] 新URL首次出现` |
| 新参数 | query string 含未知参数名 | `[URL] 新参数` |
| 频率异常 | 速率 > 基线 5 倍（30s 冷却） | `[URL] 访问频率异常` |

> URL 告警独立于 SSF/CTPG/TTT 评分，通过 `[URL]` 前缀在日志中区分。例如 HTTP 扫描器不触发任何文件 I/O 事件时，URL 基线仍可捕获异常请求模式。

### 5.2 决策阈值

| 总分 | 动作 | 实现方法 |
|------|------|---------|
| < 20 | 静默放行 | 无 |
| 20~49 | 告警 | `alarm()` → `AlertLogger.alarm()` |
| >= 50 | 告警或阻断 | `block()` → 依赖 `block.mode` |

### 5.3 追加评分详细规则

**analyzeFileSensitivity 分级评分 (TemporalGuard)**:

| 风险等级 | 匹配模式 | 加分 | 示例 |
|---------|---------|------|------|
| 最高 | 系统凭据文件 | +60 | `/etc/passwd`, `id_rsa`, `.keystore` |
| 高 | Web 容器核心配置 | +50 | `web.xml`, `server.xml`, `tomcat-users.xml` |
| 中高 | 密钥和凭据文件 | +40 | `.env`, `.key`, `.pem`, `password`, `secret` |
| 中 | 数据库/中间件配置 | +30 | `application.properties`, `mysql`, `redis` |
| 低 | config/conf 目录配置 | +20 | `config/*.properties`, `conf/*.xml` |

**analyzeCommand 敏感命令评分 (TemporalGuard)**:

| 命令 | 加分 |
|------|------|
| whoami, id, uname, hostname | +20 |
| ifconfig, ipconfig, netstat, ss, ps | +15 |
| ls, cat, dir, type, find, pwd | +10 |
| date, echo, env, ping | +5 |

### 5.4 block.mode 行为

```java
void block(String reason, StackTraceElement[] stack) {
    if (block.mode == BLOCK) {
        AlertLogger.block(reason);                    // 日志
        throw new SecurityException(reason);          // 阻断操作
    } else { // MONITOR
        AlertLogger.alarm("[MONITOR-ONLY] " + reason); // 仅告警
    }
}
```

## 6. Behinder Webshell 检测场景

### 6.1 文件管理（路径穿越/遍历）

```
攻击行为: 读取 /etc/passwd, 写 webshell, 遍历 /opt/tomcat/webapps/

触发点: checkRead / checkWrite / checkDelete
检测路径: TemporalGuard → onFileRead/Write/Delete → detectAnomaly

异常维度:
  SSF: 调用栈指纹未知 (+30)
       正常 DefaultServlet 的 doGet → serveResource 路径的指纹已在学习期入库
       Behinder 的 EqualsFilter → FileInputStream 路径指纹不在库中
       注意：RASP 内部帧已从指纹中过滤，SSF 仅包含业务代码帧
  
  CTPG: 转移链路未知 (+35)
       过滤 RASP 帧后，TRANSITION_GRAPH 中不存在 "BehinderFilter → FileInputStream" 的转移记录
  
  敏感文件: analyzeFileSensitivity 分级评分
       /etc/passwd → +60 (系统凭据)
       web.xml → +50 (核心配置)
       .env → +40 (密钥凭据)
       application.properties → +30 (数据库配置)
  
  危险类: FileInputStream/FileReader 调用 (+20 每类)

典型总分: 30 + 35 + 50~60 + 20 = 135~145 → 远超 50 阈值
```

### 6.2 命令执行

```
攻击行为: Runtime.exec("whoami"), ProcessBuilder.start("ifconfig")

触发点: checkExec
检测路径: TemporalGuard → onCommandExec → detectAnomaly

异常维度:
  SSF: 指纹未知 (+30)
       学习期 exec.jsp 的命令执行栈已被习得，但 Behinder 的调用链不同
  
  CTPG: 过滤 RASP 帧后，Runtime.exec → ProcessBuilder 转移在校验
       若学习期执行过 exec.jsp，此转移已知；否则触发 +35
  
  危险类: ProcessBuilder, Runtime.exec (+20 × N)
  
  命令分析: 敏感命令如 whoami (+20)
       普通命令如 date (+5)

典型总分: 30 + 35(若转移未知) + 60(危险类 ×3) + 20(敏感命令) = 145 → 上限 100
```

### 6.3 内存马注入

```
攻击行为: 反射调用 ClassLoader.defineClass 注入恶意 Filter

触发点: 反射调用检测 (onReflectInvoke)
检测路径: TemporalGuard → onReflectInvoke → detectAnomaly

异常维度:
  反射+文件IO组合: hasReflection && hasFileIO (+30)
  TTT SUSPICIOUS_TRANSITION: 反射 → 文件操作的转移 (+20)
  危险类: ClassLoader.defineClass (+20)

典型总分: 30 + 20 + 20 = 70
```

### 6.4 目录列举

```
攻击行为: 通过 File.listFiles() 遍历目录结构

触发点: checkRead (目录读取)
检测路径: TemporalGuard → onFileRead

异常维度:
  analyzeFileSensitivity: 遍历 Tomcat 配置目录 → +30 (含 conf/ 和 .xml)
  SSF 指纹未知 (+30)
  CTPG 转移未知 (+35)

典型总分: 30 + 35 + 30 = 95
```

### 6.5 扫描器噪声防护

```
场景: HTTP 扫描器发送 404 探测请求 (wp-admin, phpmyadmin, .git/config 等)

机制 1 — 学习期过滤 (beforeService/afterService):
  beforeService 记录请求 URI
  afterService 检查 HTTP 响应状态码
  仅 2xx/3xx 响应触发的操作被学习，404/403 响应不计入基线
  → 扫描器 404 模式不会污染学习基线

机制 2 — 检测期过滤 (isNonSensitiveDefaultServletAccess):
  HTTP 请求上下文 + 栈含 DefaultServlet/JspServlet + 文件非敏感
  → 直接跳过 detectAnomaly，不产生 CTPG/SSF 告警
  
  但敏感文件路径 (如 /.env、/config/application.properties) 的 404 探测
  因 analyzeFileSensitivity > 0，不过滤 → 正确告警

效果: 通用 404 扫描器 (wp-admin, nonexistent 等) 零误报；敏感路径探测正报告警
```

## 7. 完整检测流程（以 HTTP 请求中的文件读取为例）

```
1. 用户请求 → Tomcat HttpServlet.service()
2. ASM Hook 注入触发:
   ├─ TemporalGuard.beforeService(req) → 记录 PENDING_REQUEST_URI
   └─ 原始 service() 执行 → DefaultServlet.serveResource()
3. DefaultServlet 调用 CachedResource.validateResource() → File.canRead()
4. JDK 内部调用 SecurityManager.checkRead(webappPath)
5. RaspSecurityManager.checkRead()
   ├─ IN_DETECTION.get() → false (非重入)
   ├─ IN_DETECTION.set(true)
   ├─ TemporalGuard.onFileRead(webappPath)
   │  ├─ isSystemInternalCall(stack) → false (HTTP 请求上下文中不过滤)
   │  ├─ Thread.currentThread().getStackTrace()
   │  │   → [TemporalGuard, SecurityManager, FileInputStream,
   │  │      DefaultServlet, HttpServlet, FilterChain, ...]
   │  │   (RASP 帧 + Thread.getStackTrace 后续在 SSF/CTPG 中被过滤)
   │  ├─ BaselineLearningEngine.learnNormalStack(stack, isStartup)
   │  │   ├─ isLearningPhase? → YES: 学习过滤后的指纹, CTPG 建立转移边, 返回
   │  │   └─ isLearningPhase? → NO: 跳过学习, 进入检测
   │  ├─ isLearningPhase() → NO (检测期)
   │  ├─ isNonSensitiveDefaultServletAccess(stack, path)?
   │  │   ├─ PENDING_REQUEST_URI != null? → YES
   │  │   ├─ 栈含 DefaultServlet? → YES
   │  │   ├─ analyzeFileSensitivity(path) > 0? → 普通文件: NO → 跳过检测
   │  │   └─ 敏感性文件 (.env等): YES → 继续检测
   │  ├─ BaselineLearningEngine.detectAnomaly(stack, filePath)
   │  │   ├─ SSF: 指纹在库中? → OK (0) 或 未知 (+30)
   │  │   ├─ CTPG: 所有转移概率 > 0.01? → OK (0) 或 未知 (+35)
   │  │   ├─ TTT: 轨迹异常? → 每个 +20
   │  │   ├─ checkSensitiveFileAccess: 含敏感关键字? → 是? → +30
   │  │   └─ checkDangerousClasses: 危险类调用? → 每类 +20
   │  │   总分: 0 → 低于阈值 → 无动作
   │  ├─ analyzeFileSensitivity(path): 参数分级评分
   │  │   普通文件: 0 → 总分为 0
   │  │   /etc/passwd: +60 → 触发告警
   │  └─ 返回
   ├─ IN_DETECTION.remove()
   └─ 返回 (无异常)
6. Tomcat ASM Hook: TemporalGuard.afterService(req, res)
   ├─ 检查 HTTP 响应状态码
   ├─ 学习期:
   │   ├─ 2xx/3xx → UrlBaselineModel.learnUrl(uri)  记录 URL 和参数
   │   ├─ 2xx/3xx → learnNormalStack()              记录调用栈和 CTPG
   │   └─ 4xx/5xx → 跳过（扫描器不入基线）
   └─ 检测期:
       ├─ UrlBaselineModel.checkUrl(uri, status)      检查 URL 基线偏离
       │   ├─ 4xx/5xx → 直接返回（不告警）
       │   ├─ 路径不在基线 → [URL] 新URL首次出现
       │   ├─ 含新参数 → [URL] 新参数
       │   └─ 频率异常 → [URL] 访问频率异常
       └─ learnNormalStack()                          持续更新调用栈基线
7. FileInputStream 正常打开文件
8. Tomcat 正常返回文件内容给客户端
```

## 8. 关键设计决策

| 决策 | 原因 |
|------|------|
| 文件 I/O 用 SecurityManager 而非 ASM | Bootstrap ClassLoader 无法访问 Agent JAR 中的类 |
| 延迟安装 SecurityManager（默认 15 秒） | 避免干扰 Tomcat WebappClassLoader 部署 webapp |
| ThreadLocal 防重入 | AlertLogger 写日志 → checkWrite → TemporalGuard → 递归 → StackOverflow |
| 纯白名单基线模型 | 五层评分比单阈值更精细；学习期覆盖越多，误报越低 |
| block.mode 默认 monitor | 安全第一，先验证无误报再切换阻断 |
| 分层日志输出 | 默认只写 alarm/block/summary，debug 模式用于排查 |
| RASP 帧过滤 (StackFingerprint) | 防止 CTPG 告警显示 RASP 自身转移 (TemporalGuard → SecurityManager)，确保告警展示真实攻击链 |
| beforeService/afterService 学习期过滤 | 仅 2xx/3xx 响应触发学习，排除扫描器 404/403 污染基线 |
| isNonSensitiveDefaultServletAccess | HTTP 上下文中 DefaultServlet/JspServlet 对非敏感文件的访问跳过检测，消除扫描器 404 误报 |
| analyzeFileSensitivity 分级评分 | +60(系统凭据) / +50(核心配置) / +40(密钥) / +30(数据库配置) / +20(通用配置) — 确保敏感文件命中阈值 |
| 学习期 JSP 预编译 | JSP 编译过程中的 JDT 类加载会触发 DangerousClass 误报；学习期预编译避免检测期出现类加载噪声 |
| URL 基线独立评分 | URL 异常与 SSF/CTPG/TTT 异常是不同维度事件（如扫描器不触发 I/O 但会触发 URL 异常），独立告警避免耦合 |
| beforeService 拼接 query string | `HttpServletRequest.getRequestURI()` 不含 query string，需额外调用 `getQueryString()` 才能捕获参数用于基线学习 |
| 频率异常 30s 冷却 | 突发流量中每个请求都可能超过阈值，冷却机制防止同一路径产生告警风暴 |
| 4xx/5xx 不触发 URL 告警 | 无目的性扫描产生的 404 不是安全事件；仅后端实际处理的新 URL 和新参数才告警 |

## 9. 日志架构

### 9.1 分层设计

| 级别 | 触发频率 | 默认输出 | 调试输出 | 写入条件 |
|------|---------|---------|---------|---------|
| `debug` | 极高（每次操作） | 无 | 文件 | `debug.log=true` |
| `info` | 高 | 无 | 文件 | `verbose.info=true` |
| `warn` | 低（分钟级） | 文件 | 文件 | 始终 |
| `alarm` | 极低（仅异常） | 文件 | 文件 | 始终 |
| `block` | 极低（仅高风险） | 文件 | 文件 | 始终 |
| `error` | 极低（仅错误） | 文件+stderr | 文件+stderr | 始终 |

### 9.2 防日志洪水的三层机制

```
┌─ 第一层: 日志级别过滤 ──────────────────────┐
│ debug() → debug.log=true 才写              │
│ info()  → verbose.info=true 才写           │
│ alarm/block → 始终写（正常业务评分=0不触发） │
└────────────────────────────────────────────┘

┌─ 第二层: 计数器聚合 ────────────────────────┐
│ countReadSkipped() → AtomicLong 递增       │
│ countWriteSkipped() → AtomicLong 递增      │
│ countHttpSkipped() → AtomicLong 递增       │
│ ...                                        │
│ 每 60 秒合并为一行摘要:                      │
│ [WARN] [摘要] 近60秒: 文件读取=156 ...       │
└────────────────────────────────────────────┘

┌─ 第三层: 检测分数门控 ──────────────────────┐
│ detectAnomaly() 返回 score                 │
│ score < 20  → 无日志动作（计数器+1）         │
│ score >= 20 → alarm() 写入告警             │
│ score >= 50 → block() 写入阻断             │
│ 只有真正的异常才会产生 alarm/block 日志      │
└────────────────────────────────────────────┘
```

### 9.3 输出路径

```
alarm/block/warn → stack-anomaly-alerts.log（文件）
error            → stack-anomaly-alerts.log + stderr
debug/info       → stack-anomaly-alerts.log（仅当对应开关开启）

System.out.println → catalina.out（仅 Agent 初始化、配置加载等启动阶段消息）
```

### 9.4 日志量对比

| 模式 | 每次操作 | 每分钟 | 每小时 |
|------|---------|-------|--------|
| 优化前 | 6-8 行日志（含完整调用栈列表） | ~8.3 MB | **~500 MB** |
| 默认生产 | 计数器 +1 | 1 行摘要（~120B） | **~22 KB** |
| debug 模式 | 每操作 1-2 行 | 数千行 | 按需可变 |

### 9.5 排查开关

```bash
# 生产模式（默认，日常运维推荐）
-javaagent:...jar=block.mode=monitor

# 排查误报、验证学习覆盖度时临时开启
-javaagent:...jar=block.mode=monitor,debug.log=true

# 同时恢复 INFO 级别（更全面）
-javaagent:...jar=block.mode=monitor,debug.log=true,verbose.info=true
```
| 部署时建议在 `setenv.sh` 的 `CATALINA_OPTS/JAVA_OPTS` 中添加 |
| catch(Throwable) 全静默 | 检测逻辑任何异常都不能中断正常业务流程 |

## 10. 模型管理控制台 (Model Management Console)

### 10.1 概述

学习完成后，通过内置 JSP 页面可视化查看四种模型（SSF、CTPG、URL Profile）的学习结果，支持实时微调和重新学习。

- **访问路径**：`http://host:port/examples/model-console.jsp`（部署在 Tomcat webapps 目录下）
- **权限**：无内置认证，建议通过 Tomcat 安全域或在生产环境中仅内部可访问

### 10.2 功能列表

| 功能 | 说明 |
|------|------|
| SSF 指纹列表 | 按调用栈深度降序展示所有指纹，含 Hash、方法数、频次、阶段（启动/运行/双重），可展开查看完整调用链 |
| SSF 指纹移除 | 选中指纹后从 `NORMAL_STARTUP_FINGERPRINTS`/`NORMAL_RUNTIME_FINGERPRINTS` 中移除，后续该调用栈将触发 SSF 未知告警 |
| CTPG 转移图 | 按源方法展示所有转移关系，含总转移次数、目标方法和概率百分比。低概率转移（<1%）可直接移除 |
| CTPG 转移移除 | 从 `TransitionNode` 中移除指定目标方法，转移次数和概率即时更新 |
| URL Profile 列表 | 展示学习到的所有 URL 路径、访问次数、基线速率和参数名集合 |
| URL 路径移除 | 从 BASELINE 中移除指定路径，后续访问该路径将触发 `[URL] 新URL首次出现` 告警 |
| 重新学习 | 一键调用 `resetLearning()`，清空所有基线数据并重新进入学习阶段 |
| 强制结束学习 | 学习阶段中手动结束，立即可进入检测模式 |

### 10.3 微调即生效机制

所有修改操作通过 `HttpServlet.service()` Hook 在同一 JVM 进程内执行，直接操作内存中的并发数据结构：

```
model-console.jsp (POST action=remove_ssf&hash=xxx)
  → BaselineLearningEngine.removeFingerprint(hash)
    → NORMAL_STARTUP_FINGERPRINTS.remove(hash)
    → NORMAL_RUNTIME_FINGERPRINTS.remove(hash)
    → FINGERPRINT_OBJECTS.removeIf(...)
    → 下次 detectAnomaly() 立即使用更新后的集合
```

URL、CTPG 移除同理，修改后下一次检测立即生效，无需重启。

### 10.4 部署注意事项

- JSP 页面在首次访问时由 Jasper 编译，建议在学习期预编译（访问一次即可）
- 学习期预编译后，检测期访问不会触发 JDT 类加载告警
- `StackFingerprint` 和 `TransitionNode` 的 `public` 字段通过 JSP 直接访问
- `UrlBaseline.visitsPerMinute()` 已设为 `public` 供 JSP 调用

### 10.5 基线报告补充

模型管理控制台与自动生成的 `stack-anomaly-baseline-report.log` 互补：
- **控制台**：交互式操作，用于实时微调和验证调整效果
- **报告**：持久化归档，用于审计和离线分析

---
**版本**: 1.0.2  
**更新日期**: 2026-06-26
