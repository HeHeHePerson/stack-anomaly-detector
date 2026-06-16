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
│  │         (三种时空模型数据结构)                         ││
│  │  SSF ──── CTPG ──── TTT                             ││
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

### 2.3 调用栈采集

每次检测触发时，通过 `Thread.currentThread().getStackTrace()` 获取完整调用栈：

```
例：用户请求 /examples/servlets/index.html
  java.lang.Thread.getStackTrace
  com.defense.rasp.stackmodel.TemporalGuard.onFileRead      ← 检测入口
  com.defense.rasp.stackmodel.RaspSecurityManager.checkRead  ← SecurityManager
  java.io.FileInputStream.<init>                             ← JDK 文件读取
  org.apache.catalina.servlets.DefaultServlet.serveResource  ← Tomcat 静态资源
  org.apache.catalina.servlets.DefaultServlet.doGet          ← Servlet 处理
  javax.servlet.http.HttpServlet.service                     ← ASM Hook 注入点
  org.apache.catalina.core.ApplicationFilterChain.internalDoFilter
  org.apache.catalina.core.StandardWrapperValve.invoke
  org.apache.catalina.core.StandardContextValve.invoke
  ... (Tomcat Pipeline)
  org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun
  java.lang.Thread.run
```

## 3. 三种时空检测模型

### 3.1 SSF —— 调用栈签名指纹 (Stack Signature Fingerprint)

**数据结构**：

```java
class StackFingerprint {
    int fingerprintHash;           // 方法签名串 hashCode
    List<String> methodSignatures; // 逐帧方法签名列表
}
```

**构建过程**：
1. 从 `StackTraceElement[]` 提取每帧的 `ClassName.MethodName`
2. 拼接为 `"A.b|C.d|E.f|..."` 字符串
3. 对拼接串取 `hashCode()` 作为指纹

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

**构建过程**：遍历调用栈的相邻帧对 `(frame[i], frame[i+1])`，记录转移次数。

```
调用栈: [Z, Y, X, W, V]
转移对: Z→Y, Y→X, X→W, W→V

TRANSITION_GRAPH:
  "Z" → {Y: 5次, ...}  概率(Z→Y) = 0.3
  "Y" → {X: 8次, ...}  概率(Y→X) = 0.8
  "X" → {W: 9次, ...}  概率(X→W) = 0.7
  "W" → {V: 3次, ...}  概率(W→V) = 0.2
```

**异常判定**：

| 条件 | 分数 |
|------|------|
| 某对转移的源方法在图中不存在（从未出现过） | **+35** |
| 转移概率 < 0.01 (`MIN_NORMAL_PROBABILITY`) | **+35** |
| 转移概率 < 0.1 | **+15** |

**Behinder 攻击的 CTPG 特征**：正常 Tomcat 请求的调用链为 `HttpServlet → FilterChain → Valve → CoyoteAdapter → NioEndpoint`。Behinder 的链为 `HttpServlet → 自定义 Filter → ClassLoader.defineClass → FileOutputStream`。后者包含大量图中不存在的转移边。

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

每次调用 `learnNormalStack(stack, isStartup)` 执行三项操作：

| 操作 | 存储位置 | 用途 |
|------|---------|------|
| 注册指纹哈希 | `NORMAL_STARTUP_FINGERPRINTS` 或 `NORMAL_RUNTIME_FINGERPRINTS` | SSF 匹配 |
| 存储完整指纹对象 | `FINGERPRINT_OBJECTS` | LCS 相似度计算 |
| 建立转移边 | `TRANSITION_GRAPH` (CTPG) | 转移概率评估 |

### 4.3 学习期结束

后台守护线程每 30 秒检查一次，当 `elapsed > LEARNING_DURATION_MS` 时：
1. 设置 `isLearningPhase = false`
2. 记录学习统计（指纹数量、转移图大小）
3. 后续所有 `detectAnomaly()` 调用进入实际评分模式

## 5. 评分与决策

### 5.1 评分公式

```
总分 = min(
    SSF指纹未知(+30)
  + SSF相似度过低(+20)
  + CTPG转移未知(+35)
  + CTPG转移偏低(+15)
  + TTT轨迹异常(+20 × N条)
  + 敏感文件访问(+30)
  + 危险类调用(+20 × N类)
  + 反射+IO组合(+30)
  , 100)
```

### 5.2 决策阈值

| 总分 | 动作 | 实现方法 |
|------|------|---------|
| < 20 | 静默放行 | 无 |
| 20~49 | 告警 | `alarm()` → `AlertLogger.alarm()` |
| >= 50 | 告警或阻断 | `block()` → 依赖 `block.mode` |

### 5.3 block.mode 行为

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
  
  CTPG: 转移链路未知 (+35)
       TRANSITION_GRAPH 中不存在 "BehinderFilter → FileInputStream" 的转移记录
  
  敏感文件: 路径含 /etc/, passwd 等 (+30)

典型总分: 30 + 35 + 30 = 95 → 远超 50 阈值
```

### 6.2 命令执行

```
攻击行为: Runtime.exec("whoami"), ProcessBuilder.start("ifconfig")

触发点: checkExec
检测路径: TemporalGuard → onCommandExec → detectAnomaly

异常维度:
  SSF: 指纹未知 (+30)
  CTPG: 转移未知 (+35)
  危险类: ProcessBuilder, Runtime.exec (+20)
  命令分析: whoami 等敏感命令 (+20)

典型总分: 30 + 35 + 20 + 20 = 105 → 上限 100
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
检测路径: TemporalGuard → onFileList → detectAnomaly

异常维度:
  敏感目录: /opt/tomcat/webapps/ 等 (+30)
  CTPG 转移未知 (+35)
  SSF 指纹未知 (+30)

典型总分: 30 + 35 + 30 = 95
```

## 7. 完整检测流程（以文件读取为例）

```
1. 用户请求 → Tomcat DefaultServlet.serveResource()
2. DefaultServlet 调用 new FileInputStream(webappPath)
3. JDK 内部调用 SecurityManager.checkRead(webappPath)
4. RaspSecurityManager.checkRead()
   ├─ IN_DETECTION.get() → false (非重入)
   ├─ IN_DETECTION.set(true)
   ├─ TemporalGuard.onFileRead(webappPath)
   │  ├─ isSystemInternalCall(stack) → false (非系统调用)
   │  ├─ Thread.currentThread().getStackTrace()
   │  │   → [TemporalGuard, SecurityManager, FileInputStream,
   │  │      DefaultServlet, HttpServlet, FilterChain, ...]
   │  ├─ BaselineLearningEngine.learnNormalStack(stack, isStartup)
   │  │   ├─ isLearningPhase? → YES: 学习指纹, CTPG 建立转移边, 返回
   │  │   └─ isLearningPhase? → NO: 跳过学习, 进入检测
   │  ├─ BaselineLearningEngine.detectAnomaly(stack, filePath)
   │  │   ├─ SSF: 指纹在库中? → OK (0)
   │  │   ├─ CTPG: 所有转移概率 > 0.01? → OK (0)
   │  │   ├─ TTT: 轨迹异常? → 每个 +20
   │  │   ├─ 敏感文件? → 是? → +30
   │  │   └─ 危险类? → 无 → 0
   │  │   总分: 0 → 低于阈值 → 无动作
   │  ├─ isSensitiveFile(path) → false
   │  └─ 返回
   ├─ IN_DETECTION.remove()
   └─ 返回 (无异常)
5. FileInputStream 正常打开文件
6. Tomcat 正常返回文件内容给客户端
```

## 8. 关键设计决策

| 决策 | 原因 |
|------|------|
| 文件 I/O 用 SecurityManager 而非 ASM | Bootstrap ClassLoader 无法访问 Agent JAR 中的类 |
| 延迟安装 SecurityManager（15 秒） | 避免干扰 Tomcat WebappClassLoader 部署 webapp |
| ThreadLocal 防重入 | AlertLogger 写日志 → checkWrite → TemporalGuard → 递归 → StackOverflow |
| 纯白名单基线模型 | 五层评分比单阈值更精细；学习期覆盖越多，误报越低 |
| block.mode 默认 monitor | 安全第一，先验证无误报再切换阻断 |
| catch(Throwable) 全静默 | 检测逻辑任何异常都不能中断正常业务流程 |
