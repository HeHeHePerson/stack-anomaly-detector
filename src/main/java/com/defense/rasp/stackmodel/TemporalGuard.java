package com.defense.rasp.stackmodel;

import java.nio.file.Path;

/**
 * 统一检测入口：整合所有时空模型进行判定
 * 通过 RaspSecurityManager 拦截文件 I/O
 */
public class TemporalGuard {

    private static final int HIGH_RISK_THRESHOLD = 50;
    private static final int MEDIUM_RISK_THRESHOLD = 20;

    private static boolean isSystemInternalCall(StackTraceElement[] stack) {
        if (stack == null || stack.length == 0) return true;
        
        for (int i = 1; i < stack.length; i++) {
            String className = stack[i].getClassName();
            if (className.startsWith("sun.misc.") ||
                className.startsWith("sun.nio.") ||
                className.startsWith("jdk.internal.") ||
                className.startsWith("java.lang.Shutdown") ||
                className.startsWith("java.lang.ApplicationShutdownHooks") ||
                className.startsWith("sun.launcher.") ||
                className.startsWith("org.apache.catalina.startup.") ||
                className.startsWith("org.apache.catalina.core.") ||
                className.startsWith("org.apache.catalina.util.") ||
                className.startsWith("org.apache.tomcat.") ||
                className.startsWith("org.apache.coyote.") ||
                className.startsWith("java.util.concurrent.") ||
                className.startsWith("java.util.Timer") ||
                className.startsWith("java.lang.Thread")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isNonSensitiveDefaultServletAccess(StackTraceElement[] stack, String filePath) {
        if (PENDING_REQUEST_URI.get() == null) return false;
        if (stack == null || stack.length == 0) return false;
        if (analyzeFileSensitivity(filePath) > 0) return false;

        for (int i = 1; i < stack.length; i++) {
            String className = stack[i].getClassName();
            if (className.equals("org.apache.catalina.servlets.DefaultServlet") ||
                className.startsWith("org.apache.jasper.servlet.JspServlet") ||
                className.startsWith("org.apache.catalina.loader.") ||
                className.startsWith("org.apache.jasper.compiler.") ||
                className.startsWith("org.apache.jasper.runtime.") ||
                className.startsWith("java.util.ResourceBundle")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isJarOrClassFile(String filePath) {
        if (filePath == null) return false;
        String lower = filePath.toLowerCase();
        return lower.endsWith(".jar") || lower.endsWith(".zip") ||
               lower.endsWith(".class") || lower.endsWith(".war");
    }

    public static void onFileList(java.io.File dir) {
        if (dir == null) return;
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        if (PENDING_REQUEST_URI.get() == null && isSystemInternalCall(stack)) return;
        
        String dirPath = dir.getAbsolutePath();
        AlertLogger.debug("[TemporalGuard] 目录列举检测触发: " + dirPath);
        recordThreadEvent("java.io.FileSystem.list", StackTemporalEngine.CallEvent.EventType.ENTER);
        
        long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
        boolean isStartup = jvmUptime < 120_000;
        
        BaselineLearningEngine.learnNormalStack(stack, isStartup);
        
        if (BaselineLearningEngine.isLearningPhase()) {
            AlertLogger.debug("[TemporalGuard] 学习期目录列举: " + dirPath);
            return;
        }
        
        if (isNonSensitiveDefaultServletAccess(stack, dirPath)) return;
        
        int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, dirPath);
        
        if (isSensitiveDirectory(dirPath)) {
            anomalyScore += 30;
            AlertLogger.alarm("[SensitiveDir] 检测到敏感目录列举: " + dirPath + " 分数=+30");
            checkCorrelation(20);
        }
        
        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险目录列举: 目录=" + dirPath, anomalyScore, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险目录列举: 目录=" + dirPath, anomalyScore, stack);
        }
    }

    public static void onPathRead(Path path) {
        if (path != null) onFileRead(path.toString());
    }

    public static void onPathWrite(Path path) {
        if (path != null) onFileWrite(path.toString());
    }

    public static void onPathDelete(Path path) {
        if (path != null) onFileDelete(path.toString());
    }

    public static void onFileRead(String filePath) {
        if (filePath == null) return;
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        // HTTP 请求上下文中的文件读取不视为系统内部调用，确保冰蝎等 Webshell 的文件读取能被检测
        if (PENDING_REQUEST_URI.get() == null && isSystemInternalCall(stack)) {
            AlertLogger.debug("[TemporalGuard] 系统内部文件读取: " + filePath);
            return;
        }

        AlertLogger.debug("[TemporalGuard] 文件读取检测触发: " + filePath);
        recordThreadEvent("java.io.FileInputStream.<init>", StackTemporalEngine.CallEvent.EventType.ENTER);
        
        long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
        boolean isStartup = jvmUptime < 120_000;

        BaselineLearningEngine.learnNormalStack(stack, isStartup);
        
        if (BaselineLearningEngine.isLearningPhase()) {
            AlertLogger.debug("[TemporalGuard] 学习期文件读取: " + filePath);
            AlertLogger.countReadSkipped();
            return;
        }
        
        if (isNonSensitiveDefaultServletAccess(stack, filePath)) {
            AlertLogger.countReadSkipped();
            return;
        }

        if (isJarOrClassFile(filePath)) return;

        int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, filePath);
        anomalyScore += analyzeFileSensitivity(filePath);

        if (IN_DESERIALIZATION.get() != null && IN_DESERIALIZATION.get()) {
            anomalyScore += 25;
            AlertLogger.alarm("[DeserializationCtx] 反序列化上下文中的文件读取: "
                + filePath + " 分数=+25");
        }

        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险时空异常: 文件=" + filePath, anomalyScore, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险时空异常: 文件=" + filePath, anomalyScore, stack);
        } else {
            AlertLogger.countReadSkipped();
        }
    }

    public static void onFileWrite(String filePath) {
        if (filePath == null) return;
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        if (PENDING_REQUEST_URI.get() == null && isSystemInternalCall(stack)) {
            AlertLogger.debug("[TemporalGuard] 系统内部文件写入: " + filePath);
            return;
        }

        AlertLogger.debug("[RaspSecurityManager] 文件写入拦截: " + filePath);
        recordThreadEvent("java.io.FileOutputStream.<init>", StackTemporalEngine.CallEvent.EventType.ENTER);
        
        BaselineLearningEngine.learnNormalStack(stack, false);
        
        if (BaselineLearningEngine.isLearningPhase()) {
            AlertLogger.debug("[TemporalGuard] 学习期文件写入: " + filePath);
            AlertLogger.countWriteSkipped();
            return;
        }
        
        if (isNonSensitiveDefaultServletAccess(stack, filePath)) {
            AlertLogger.countWriteSkipped();
            return;
        }
        
        int score = BaselineLearningEngine.detectAnomaly(stack, filePath);
        score += analyzeFileSensitivity(filePath);
        
        if (score >= HIGH_RISK_THRESHOLD) {
            block("高风险文件写入: 文件=" + filePath, score, stack);
        } else if (score >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险文件写入: 文件=" + filePath, score, stack);
        } else {
            AlertLogger.countWriteSkipped();
        }
    }

    public static void onFileDelete(String filePath) {
        if (filePath == null) return;
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        if (PENDING_REQUEST_URI.get() == null && isSystemInternalCall(stack)) {
            AlertLogger.debug("[TemporalGuard] 系统内部文件删除: " + filePath);
            return;
        }

        AlertLogger.debug("[RaspSecurityManager] 文件删除拦截: " + filePath);
        recordThreadEvent("java.io.File.delete", StackTemporalEngine.CallEvent.EventType.ENTER);
        
        BaselineLearningEngine.learnNormalStack(stack, false);
        
        if (BaselineLearningEngine.isLearningPhase()) {
            AlertLogger.debug("[TemporalGuard] 学习期文件删除: " + filePath);
            AlertLogger.countDeleteSkipped();
            return;
        }
        
        if (isNonSensitiveDefaultServletAccess(stack, filePath)) {
            AlertLogger.countDeleteSkipped();
            return;
        }
        
        int score = BaselineLearningEngine.detectAnomaly(stack, filePath);
        score += analyzeFileSensitivity(filePath);
        
        if (score >= HIGH_RISK_THRESHOLD) {
            block("高风险文件删除: 文件=" + filePath, score, stack);
        } else if (score >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险文件删除: 文件=" + filePath, score, stack);
        } else {
            AlertLogger.countDeleteSkipped();
        }
    }

    // 延迟学习：在 beforeService 记录 URI，afterService 根据响应状态决定是否学习
    private static final ThreadLocal<String> PENDING_REQUEST_URI = new ThreadLocal<>();
    private static final ThreadLocal<String> REMOTE_ADDR = new ThreadLocal<>();
    private static final ThreadLocal<String> BLOCK_REASON = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> IS_BANNED = new ThreadLocal<>();
    private static final ThreadLocal<String> FP_FINGERPRINT = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> AFTER_RAN = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> IN_DESERIALIZATION = new ThreadLocal<>();

    public static void beforeDeserialization() {
        IN_DESERIALIZATION.set(true);
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        recordThreadEvent("spring.messageconverter.read", StackTemporalEngine.CallEvent.EventType.ENTER);
        BaselineLearningEngine.learnNormalStack(stack, false);
    }

    public static void afterDeserialization() {
        IN_DESERIALIZATION.remove();
    }

    public static String getCurrentUri() {
        return PENDING_REQUEST_URI.get();
    }

    public static void beforeService(Object req, Object res) {
        AlertLogger.debug("[TemporalGuard] beforeService 被调用");
        if (req == null) return;
        try {
            java.lang.reflect.Method m = req.getClass().getMethod("getRequestURI");
            String uri = (String) m.invoke(req);
            try {
                java.lang.reflect.Method qm = req.getClass().getMethod("getQueryString");
                String query = (String) qm.invoke(req);
                if (query != null && !query.isEmpty()) {
                    uri = uri + "?" + query;
                }
            } catch (Exception ignored) {
            }
            PENDING_REQUEST_URI.set(uri);
            try {
                java.lang.reflect.Method rm = req.getClass().getMethod("getRemoteAddr");
                String addr = (String) rm.invoke(req);
                if (addr != null) REMOTE_ADDR.set(addr);
            } catch (Exception ignored) {
            }
            readFingerprintAndCheckBan(req, res);
            AlertLogger.debug("[TemporalGuard] beforeService URI: " + uri);
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            AlertLogger.debug("[TemporalGuard] beforeService 失败: " + e.getMessage());
        }
    }

    private static void readFingerprintAndCheckBan(Object req, Object res) {
        try {
            java.lang.reflect.Method getCookies = req.getClass().getMethod("getCookies");
            Object[] cookies = (Object[]) getCookies.invoke(req);
            if (cookies != null) {
                for (Object cookie : cookies) {
                    java.lang.reflect.Method getName = cookie.getClass().getMethod("getName");
                    String name = (String) getName.invoke(cookie);
                    if ("X-RASP-FP".equals(name)) {
                        java.lang.reflect.Method getValue = cookie.getClass().getMethod("getValue");
                        String fp = (String) getValue.invoke(cookie);
                        if (fp != null && !fp.isEmpty()) {
                            FP_FINGERPRINT.set(fp);
                            if (FingerprintBanEngine.isBanned(fp)) {
                                long remaining = FingerprintBanEngine.getBanRemainingSeconds(fp);
                                sendBlockedPage(req, res, "浏览器指纹已封禁，剩余 " + remaining + " 秒", true);
                                return;
                            }
                        }
                        break;
                    }
                }
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Exception ignored) {
        }
    }

    public static void afterService(Object req, Object res) {
        if (AFTER_RAN.get() != null) return;
        AFTER_RAN.set(true);
        try {
            String uri = PENDING_REQUEST_URI.get();
            String blockReason = BLOCK_REASON.get();
            boolean banned = IS_BANNED.get() != null;
            PENDING_REQUEST_URI.remove();
            REMOTE_ADDR.remove();
            BLOCK_REASON.remove();
            IS_BANNED.remove();
            FP_FINGERPRINT.remove();

            if (blockReason != null || banned) {
                String reason = blockReason != null ? blockReason : "指纹封禁";
                sendBlockedPage(req, res, reason, banned);
                return;
            }

            if (uri == null) return;

            int status = -1;
            try {
                java.lang.reflect.Method m = res.getClass().getMethod("getStatus");
                status = (Integer) m.invoke(res);
            } catch (Exception e) {
            }

            if (BaselineLearningEngine.isLearningPhase()) {
                if (status >= 200 && status < 400) {
                    UrlBaselineModel.learnUrl(uri);
                }
                if (status < 200 || status >= 400) {
                    AlertLogger.debug("[TemporalGuard] 学习期跳过非成功响应: " + uri + " (status=" + status + ")");
                    return;
                }
            } else {
                UrlBaselineModel.checkUrl(uri, status);
            }

            AlertLogger.debug("[TemporalGuard] HTTP 请求: " + uri);
            recordThreadEvent("HttpServlet.service", StackTemporalEngine.CallEvent.EventType.ENTER);
            long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
            BaselineLearningEngine.learnNormalStack(Thread.currentThread().getStackTrace(), jvmUptime < 120_000);
            AlertLogger.countHttpSkipped();
        } finally {
            AFTER_RAN.remove();
        }
    }

    public static void onServletContextAccess(String path) {
        if (path != null) {
            AlertLogger.debug("[TemporalGuard] ServletContext 访问: " + path);
            recordThreadEvent("ServletContext." + path, StackTemporalEngine.CallEvent.EventType.ENTER);
        }
    }

    public static void onReflectInvoke(String[] methodInfo) {
        if (methodInfo == null || methodInfo.length != 2) return;
        
        String fullSignature = methodInfo[0] + "." + methodInfo[1];
        AlertLogger.debug("[TemporalGuard] 反射调用检测触发: " + fullSignature);
        recordThreadEvent(fullSignature, StackTemporalEngine.CallEvent.EventType.ENTER);
        
        if (isSensitiveReflectCall(methodInfo[0], methodInfo[1])) {
            if (BaselineLearningEngine.isLearningPhase()) {
                AlertLogger.debug("[TemporalGuard] 学习期跳过反射告警: " + fullSignature);
                return;
            }
            
            AlertLogger.alarm("[ReflectDetector] 检测到敏感方法的反射调用: " + fullSignature);
            checkCorrelation(20);
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, null);
            
            if (anomalyScore >= HIGH_RISK_THRESHOLD) {
                block("高风险反射调用: 方法=" + fullSignature, anomalyScore, stack);
            } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
                alarm("中风险反射调用: 方法=" + fullSignature, anomalyScore, stack);
            }
        }
    }

    public static void onSuspiciousOutboundConnection(String host, int port) {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        recordThreadEvent("java.net.Socket.connect", StackTemporalEngine.CallEvent.EventType.ENTER);
        BaselineLearningEngine.learnNormalStack(stack, false);
        if (BaselineLearningEngine.isLearningPhase()) return;

        int score = 30;
        if (port == 389 || port == 636 || port == 3268 || port == 3269) score += 20;
        if (port == 1099 || port == 1098 || port == 1389 || port == 1387 || port == 2000) score += 20;

        score += BaselineLearningEngine.detectAnomaly(stack, host + ":" + port);

        if (score >= HIGH_RISK_THRESHOLD) {
            block("高风险外连: " + host + ":" + port, score, stack);
        } else if (score >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险外连: " + host + ":" + port, score, stack);
        }
        checkCorrelation(score);
    }

    private static boolean isSensitiveReflectCall(String className, String methodName) {
        if (className.startsWith("java.io") || className.startsWith("java.nio")) return true;
        if (className.startsWith("java.lang.ClassLoader") || className.startsWith("sun.misc.Launcher")) return true;
        if (className.equals("java.lang.reflect.Method") && 
            (methodName.equals("invoke") || methodName.equals("invokeExact"))) return true;
        if (className.equals("java.lang.reflect.Constructor") && methodName.equals("newInstance")) return true;
        if (className.startsWith("java.lang.reflect.Field") && 
            (methodName.equals("get") || methodName.equals("set") || methodName.equals("getBoolean"))) return true;
        return false;
    }

    public static void onCommandExec(String command) {
        if (command == null || command.isEmpty()) return;
        AlertLogger.debug("[TemporalGuard] 命令执行检测触发: " + command);
        
        long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
        boolean isStartup = jvmUptime < 120_000;
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();

        BaselineLearningEngine.learnNormalStack(stack, isStartup);
        
        if (BaselineLearningEngine.isLearningPhase()) {
            AlertLogger.debug("[TemporalGuard] 学习期命令执行: " + command);
            AlertLogger.countExecSkipped();
            return;
        }
        
        int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, null) + analyzeCommand(command);

        if (IN_DESERIALIZATION.get() != null && IN_DESERIALIZATION.get()) {
            anomalyScore += 25;
            AlertLogger.alarm("[DeserializationCtx] 反序列化上下文中的命令执行: "
                + command + " 分数=+25");
        }

        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险命令执行: 命令=" + command, anomalyScore, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险命令执行: 命令=" + command, anomalyScore, stack);
        } else {
            AlertLogger.countExecSkipped();
        }
    }
    
    public static void onProcessBuilderStart(java.util.List<String> cmdList) {
        if (cmdList == null || cmdList.isEmpty()) return;
        onCommandExec(String.join(" ", cmdList));
    }

    private static int analyzeCommand(String command) {
        int score = 0;
        String lowerCommand = command.toLowerCase();

        String[] dangerousCommands = {
            "cat", "type", "more", "head", "tail", "cp", "copy", "move", "mv", "rm", "del",
            "find", "grep", "awk", "sed", "vim", "vi", "nano",
            "powershell", "cmd", "bash", "sh", "zsh", "python", "perl", "ruby", "php",
            "curl", "wget", "nc", "netcat", "telnet", "chmod", "chown", "sudo", "su", "whoami"
        };

        String[] sensitiveFileKeywords = {
            "tomcat-users", "server.xml", "web.xml", "context.xml",
            ".properties", ".yml", ".env", ".key", ".pem", "passwd", "shadow",
            "mysql", "postgres", "redis", "rabbitmq", "kafka", "ssh/",
            "authorized_keys", "id_rsa", "/etc/passwd"
        };

        String[] suspiciousPatterns = {
            "|", ";", "&&", "||", "$(", "`", ">", "<", "base64", "decode",
            "bash -i", "python -c", "cmd.exe", "cmd /c", "powershell -c", "nc -e"
        };

        for (String cmd : dangerousCommands) {
            if (lowerCommand.contains(cmd)) { score += 10; }
        }
        for (String keyword : sensitiveFileKeywords) {
            if (lowerCommand.contains(keyword)) { score += 30; }
        }
        for (String pattern : suspiciousPatterns) {
            if (lowerCommand.contains(pattern)) { score += 15; }
        }
        
        return score;
    }

    private static int analyzeFileSensitivity(String filePath) {
        if (filePath == null) return 0;
        String lowerPath = filePath.toLowerCase();
        if (lowerPath.endsWith(".jar") || lowerPath.endsWith(".zip") ||
            lowerPath.endsWith(".class") || lowerPath.endsWith(".war")) {
            return 0;
        }
        int score = 0;

        // 最高风险：系统凭据文件和密钥
        String[] criticalFiles = {
            "/etc/passwd", "/etc/shadow", "id_rsa", "authorized_keys",
            ".keystore", ".truststore", ".jks", ".p12", ".pfx"
        };
        for (String kw : criticalFiles) {
            if (lowerPath.contains(kw)) {
                AlertLogger.alarm("[SensitiveFile] 高风险文件访问: " + filePath + " 分数=+60");
                score += 60;
                break;
            }
        }

        // 高风险：Web 容器核心配置
        String[] highRiskFiles = {
            "tomcat-users.xml", "server.xml", "web.xml", "context.xml",
            "catalina.properties", "catalina.policy"
        };
        for (String kw : highRiskFiles) {
            if (lowerPath.contains(kw)) {
                AlertLogger.alarm("[SensitiveFile] 高风险配置访问: " + filePath + " 分数=+50");
                score += 50;
                break;
            }
        }

        // 中高风险：密钥和凭证文件
        String[] credentialFiles = {
            ".key", ".pem", ".env", ".crt", ".cer", "private", "secret",
            "password", "credential", "token"
        };
        for (String kw : credentialFiles) {
            if (lowerPath.contains(kw)) {
                score += 40;
                break;
            }
        }

        // 中风险：配置和数据库相关
        // 排除标准 Java 库包路径 (com/mysql, org/postgresql 等)，避免资源文件误报
        String[] mediumRiskFiles = {
            "application.properties", "application.yml", "logback.xml",
            "log4j", "jdbc.properties", "mysql", "postgres", "redis",
            "rabbitmq", "kafka", "nacos", "consul",
            "applicationcontext", "spring-servlet", "mybatis", "mapper",
            "hibernate", "persistence.xml", "struts"
        };
        for (String kw : mediumRiskFiles) {
            if (lowerPath.contains(kw)) {
                if (isJavaPackagePath(lowerPath, kw)) {
                    continue;
                }
                score += 30;
                break;
            }
        }

        // 低风险：config/conf 目录下的配置文件
        if ((lowerPath.contains("config") || lowerPath.contains("conf")) && 
            (lowerPath.endsWith(".properties") || lowerPath.endsWith(".xml") ||
             lowerPath.endsWith(".yml") || lowerPath.endsWith(".yaml") ||
             lowerPath.endsWith(".conf") || lowerPath.endsWith(".policy") ||
             lowerPath.endsWith(".xsd"))) {
            score += 20;
        }

        return score;
    }

    private static boolean isJavaPackagePath(String lowerPath, String keyword) {
        return lowerPath.contains("/com/" + keyword + "/") ||
               lowerPath.contains("/org/" + keyword + "/") ||
               lowerPath.contains("/net/" + keyword + "/") ||
               lowerPath.contains("\\com\\" + keyword + "\\") ||
               lowerPath.contains("\\org\\" + keyword + "\\") ||
               lowerPath.contains("\\net\\" + keyword + "\\");
    }

    private static boolean isSensitiveDirectory(String dirPath) {
        if (dirPath == null) return false;
        String lowerPath = dirPath.toLowerCase();
        
        String[] sensitive = {
            "tomcat/conf", "tomcat/logs", "catalina/conf", "webapps/web-inf",
            "webapps/meta-inf", "/etc/", "windows/system32", ".ssh/", ".git/", ".svn/"
        };
        
        for (String s : sensitive) {
            if (lowerPath.contains(s)) return true;
        }
        return false;
    }

    private static void sendBlockedPage(Object req, Object res, String reason, boolean isBanned) {
        try {
            java.lang.reflect.Method reset = res.getClass().getMethod("reset");
            reset.invoke(res);
        } catch (Exception ignored) {
        }
        try {
            java.lang.reflect.Method setStatus = res.getClass().getMethod("setStatus", int.class);
            setStatus.invoke(res, 403);
            java.lang.reflect.Method setContentType = res.getClass().getMethod("setContentType", String.class);
            setContentType.invoke(res, "text/html; charset=UTF-8");

            StringBuilder html = new StringBuilder(4096);
            html.append("<!DOCTYPE html>\n");
            html.append("<html lang=\"zh-CN\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>访问被阻断</title>");
            html.append("<style>");
            html.append("*{margin:0;padding:0;box-sizing:border-box}");
            html.append("body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0e27;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh}");
            html.append(".card{background:#111640;border:1px solid #1e2358;border-radius:12px;padding:48px;max-width:520px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,0.4)}");
            html.append(".icon{font-size:56px;margin-bottom:16px;color:#ff4757}");
            html.append("h1{font-size:24px;margin-bottom:12px;color:#ff6b7a}");
            html.append("p{font-size:14px;color:#8890b5;line-height:1.6;margin-bottom:8px}");
            html.append(".reason{background:#0d1130;border:1px solid #1e2358;border-radius:6px;padding:12px;margin:16px 0;font-size:12px;color:#ff6b7a;word-break:break-all}");
            html.append(".footer{margin-top:24px;font-size:11px;color:#4a5080}");
            html.append("</style></head><body>");
            html.append("<div class=\"card\">");
            html.append("<div class=\"icon\">&#128737;</div>");
            html.append("<h1>").append(isBanned ? "访问受限" : "请求已被阻断").append("</h1>");
            html.append("<p>").append(isBanned ? "您的浏览器指纹已被临时封禁" : "安全系统检测到异常行为，已阻止本次请求").append("</p>");
            html.append("<div class=\"reason\">").append(escapeHtml(reason)).append("</div>");
            html.append("<p>若您认为这是误判，请联系系统管理员。</p>");
            html.append("<div class=\"footer\"><span id=\"fp\"></span><br>Security by RASP &mdash; Stack Anomaly Detector</div>");
            html.append("</div>");
            html.append("<script>");
            html.append("(function(){var s=[];");
            html.append("try{var c=document.createElement('canvas');c.width=280;c.height=60;var x=c.getContext('2d');");
            html.append("var g=x.createLinearGradient(0,0,280,60);g.addColorStop(0,'#1a73e8');g.addColorStop(0.5,'#ea4335');g.addColorStop(1,'#34a853');x.fillStyle=g;x.fillRect(0,0,280,60);");
            html.append("x.textBaseline='top';x.font='16px Arial';x.fillStyle='#fff';x.fillText('RASP Security',10,5);");
            html.append("x.font='12px \"Times New Roman\"';x.fillStyle='rgba(255,255,255,0.85)';x.fillText('Browser Fingerprint',10,28);");
            html.append("x.font='bold 10px \"Courier New\"';x.fillStyle='rgba(200,200,255,0.9)';x.fillText('Canvas|WebGL|CPU',10,48);");
            html.append("x.beginPath();x.arc(250,30,15,0,Math.PI*2,false);x.fillStyle='rgba(255,255,0,0.3)';x.fill();");
            html.append("s.push('cv:'+h(c.toDataURL().substring(300)))}catch(e){s.push('cv:err')}");
            html.append("try{var w=document.createElement('canvas').getContext('webgl')||document.createElement('canvas').getContext('experimental-webgl');if(w){var d=w.getExtension('WEBGL_debug_renderer_info');if(d)s.push('gl:'+h(w.getParameter(d.UNMASKED_RENDERER_WEBGL)))}}catch(e){s.push('gl:err')}");
            html.append("s.push('hc:'+(navigator.hardwareConcurrency||'unknown'));");
            html.append("function h(str){var v=0;for(var i=0;i<str.length;i++){v=((v<<5)-v)+str.charCodeAt(i);v|=0}return(v>>>0).toString(36)}");
            html.append("var fp=h(s.join('|'));document.cookie='X-RASP-FP='+fp+';path=/;max-age=86400;SameSite=Lax';var e=document.getElementById('fp');if(e)e.textContent='FP: '+fp");
            html.append("})();</script>");
            html.append("</body></html>");

            byte[] bytes = html.toString().getBytes("UTF-8");
            java.lang.reflect.Method setContentLength = res.getClass().getMethod("setContentLength", int.class);
            setContentLength.invoke(res, bytes.length);
            java.lang.reflect.Method getOutputStream = res.getClass().getMethod("getOutputStream");
            java.io.OutputStream os = (java.io.OutputStream) getOutputStream.invoke(res);
            os.write(bytes);
            os.flush();
        } catch (Exception e) {
            System.err.println("[TemporalGuard] 阻断页面发送失败: " + e.getMessage());
        }
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '&': sb.append("&amp;"); break;
                case '"': sb.append("&quot;"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    private static void block(String reason, int score, StackTraceElement[] stack) {
        com.defense.rasp.agent.AgentConfig.BlockMode mode = 
                com.defense.rasp.agent.AgentConfig.getBlockMode();
        
        if (mode == com.defense.rasp.agent.AgentConfig.BlockMode.BLOCK) {
            AlertLogger.block("[TemporalGuard] 分数=" + score + ", " + reason);
            AlertLogger.error("[TemporalGuard] 调用栈:\n" + formatStack(stack));
            checkCorrelation(score);
            BLOCK_REASON.set(reason);
            recordFingerprintAttack();
            throw new SecurityException("[TemporalGuard] 阻断异常调用: " + reason);
        } else {
            AlertLogger.alarm("[MONITOR-ONLY] 分数=" + score + ", " + reason + " (仅告警模式)");
            checkCorrelation(score);
        }
    }

    private static void alarm(String reason, int score, StackTraceElement[] stack) {
        AlertLogger.alarm("[TemporalGuard] 分数=" + score + ", " + reason);
        checkCorrelation(score);
    }

    private static void checkCorrelation(int score) {
        String remoteAddr = REMOTE_ADDR.get();
        if (remoteAddr == null || score <= 0) return;
        if (AttackCorrelationEngine.recordScore(remoteAddr, score)) {
            AlertLogger.warn("[CORRELATION] IP " + remoteAddr
                + " 在 " + AttackCorrelationEngine.getWindowSeconds() + "s 内累计风险分数超过阈值 "
                + AttackCorrelationEngine.getScoreThreshold());
        }
    }

    private static void recordFingerprintAttack() {
        String fp = FP_FINGERPRINT.get();
        if (fp != null) {
            FingerprintBanEngine.recordAttack(fp);
        }
    }

    private static String formatStack(StackTraceElement[] stack) {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement e : stack) {
            sb.append("\tat ").append(e.toString()).append("\n");
        }
        return sb.toString();
    }

    private static void recordThreadEvent(String method, StackTemporalEngine.CallEvent.EventType type) {
        long threadId = Thread.currentThread().getId();
        String threadName = Thread.currentThread().getName();
        StackTemporalEngine.ThreadTrajectory trajectory =
                StackTemporalEngine.getOrCreateTrajectory(threadId, threadName);
        trajectory.addEvent(new StackTemporalEngine.CallEvent(System.currentTimeMillis(), method, type));
    }
}
