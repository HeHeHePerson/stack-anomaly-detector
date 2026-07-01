# 模型管理控制台 JSP 部署与使用说明

## 1. 概述

`model-console.jsp` 是 Stack Anomaly Detector 的内置 Web 管理控制台，提供 SSF 调用栈指纹、CTPG 管控转移概率图和 URL Profile 三种检测模型的可视化查看与微调能力。

## 2. 文件位置

- **工程源文件**：`src/main/webapp/model-console.jsp`
- **部署目标**：`$CATALINA_BASE/webapps/examples/model-console.jsp`

## 3. 部署步骤

### 3.1 首次部署

```bash
# 复制 JSP 到 Tomcat webapps 目录
cp src/main/webapp/model-console.jsp $CATALINA_BASE/webapps/examples/model-console.jsp
```

### 3.2 更新部署

```bash
# 复制更新后的 JSP
cp src/main/webapp/model-console.jsp $CATALINA_BASE/webapps/examples/model-console.jsp

# 清理 Jasper 编译缓存（必须执行）
rm -rf $CATALINA_BASE/work/Catalina/localhost/examples/org/apache/jsp/model*
```

### 3.3 学习期预编译

建议在学习阶段预先访问一次 JSP，使其由 Jasper 编译为 class 文件，避免检测阶段触发 JDT 类加载告警：

```bash
curl -s http://localhost:8080/examples/model-console.jsp > /dev/null
```

## 4. 访问方式

```
http://<host>:<port>/examples/model-console.jsp
```

## 5. 功能说明

### 5.1 标签页

| 标签页 | 内容 |
|--------|------|
| SSF 调用栈指纹 | 展示所有学习到的调用栈指纹，按调用深度降序排列。支持展开/折叠完整方法调用链 |
| CTPG 管控转移概率图 | 展示所有方法转移关系及转移概率，按源方法分组 |
| URL Profile | 展示学习到的 URL 路径、访问次数、基线速率、参数名集合和参数值最大长度 |
| 阈值在线设置 | URL 标签页支持在线调整频率阈值（1.0-10.0x）和参数值长度阈值（100%-1000%），修改即时生效 |

### 5.2 操作按钮

| 操作 | 按钮 | 说明 |
|------|------|------|
| 重新学习 | `重新学习` | 清空所有基线数据，重新进入学习阶段 |
| 强制结束学习 | `强制结束学习` | 提前结束当前学习阶段，立即进入检测模式 |
| 刷新数据 | `刷新数据` | 重新加载当前标签页数据（GET 请求，不修改模型） |

### 5.3 微调操作

| 操作 | 触发条件 | 效果 |
|------|----------|------|
| 移除 SSF 指纹 | 点击指纹旁的 `移除` 按钮 | 从启动/运行时指纹集合中移除，后续该调用栈将触发 SSF 未知告警 |
| 移除 CTPG 转移 | 点击低概率转移旁的 `移除` 按钮 | 从 TransitionNode 中移除指定目标方法 |
| 移除 URL 路径 | 点击 URL 路径旁的 `移除` 按钮 | 从 URL 基线中移除，后续访问触发新 URL 告警 |

## 6. 数据流

```
model-console.jsp (POST action=remove_ssf&hash=xxx)
  └→ BaselineLearningEngine.removeFingerprint(hash)
     └→ NORMAL_STARTUP_FINGERPRINTS/NORMAL_RUNTIME_FINGERPRINTS.remove(hash)
        └→ FINGERPRINT_OBJECTS.removeIf(...)
           └→ 标记为 "[ModelMgmt] 移除SSF指纹: hash"
```

所有修改操作在 JVM 内存中直接执行，修改后下一次请求即生效，无需重启 Tomcat。

## 7. 依赖关系

JSP 页面通过 `HttpServlet.service()` Hook 注入的上下文访问以下 Java 类：

| 类 | 用途 |
|----|------|
| `BaselineLearningEngine` | SSF/CTPG 模型查询与修改 |
| `StackTemporalEngine` | SSF 指纹对象与 CTPG 转移图数据结构 |
| `UrlBaselineModel` | URL Profile 模型查询与修改 |

类通过 `-javaagent` 的系统 ClassLoader 加载，`WebappClassLoader` 通过层级委托机制可访问。

## 8. 日志记录

所有修改操作记录在 `stack-anomaly-alerts.log` 中，前缀为 `[ModelMgmt]`：

```
[2026-06-26 03:22:36.197] [WARN] [ModelMgmt] 移除SSF指纹: 1075983140
[2026-06-26 03:22:43.105] [WARN] [ModelMgmt] 移除URL基线路径: /examples
[2026-06-26 03:22:43.163] [WARN] [BaselineLearning] 学习状态已重置
```

## 9. 安全建议

- JSP 页面无内置认证，建议生产环境通过 Tomcat `security-constraint` 配置 BASIC 认证
- 在 `$CATALINA_BASE/webapps/examples/WEB-INF/web.xml` 中添加：

```xml
<security-constraint>
    <web-resource-collection>
        <web-resource-name>Model Console</web-resource-name>
        <url-pattern>/model-console.jsp</url-pattern>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
<login-config>
    <auth-method>BASIC</auth-method>
    <realm-name>Model Console</realm-name>
</login-config>
```

- 在 `$CATALINA_BASE/conf/tomcat-users.xml` 中配置管理员用户
- 仅内部网络可访问该页面

## 10. 故障排查

| 问题 | 原因 | 解决 |
|------|------|------|
| JSP 修改后不生效 | Jasper 缓存了旧编译文件 | 清理 work 目录：`rm -rf $CATALINA_BASE/work/Catalina/localhost/examples/org/apache/jsp/model*` |
| 页面显示"学习中"但无数据 | SSF 数据在学习结束后才可用 | 等待学习完成或使用"强制结束学习" |
| 页面空白/500 错误 | Jasper 编译失败 | 检查日志，确认 JSP 语法正确，无 lambda 表达式 |
| ClassNotFoundException | Agent jar 未加载到系统 classloader | 确认使用 javaagent 而非 tomcat classpath 加载 |

---

**版本**: 1.0.1  
**更新日期**: 2026-07-01
