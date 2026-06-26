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
                className.startsWith("org.apache.jasper.servlet.JspServlet")) {
                return true;
            }
        }
        return false;
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
            AlertLogger.alarm("[SensitiveDir] 检测到敏感目录列举: " + dirPath);
        }
        
        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险目录列举: 分数=" + anomalyScore + ", 目录=" + dirPath, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险目录列举: 分数=" + anomalyScore + ", 目录=" + dirPath, stack);
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
        
        int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, filePath);
        anomalyScore += analyzeFileSensitivity(filePath);

        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险时空异常: 分数=" + anomalyScore + ", 文件=" + filePath, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险时空异常: 分数=" + anomalyScore + ", 文件=" + filePath, stack);
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
            block("高风险文件写入: 分数=" + score + ", 文件=" + filePath, stack);
        } else if (score >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险文件写入: 分数=" + score + ", 文件=" + filePath, stack);
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
            block("高风险文件删除: 分数=" + score + ", 文件=" + filePath, stack);
        } else if (score >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险文件删除: 分数=" + score + ", 文件=" + filePath, stack);
        } else {
            AlertLogger.countDeleteSkipped();
        }
    }

    // 延迟学习：在 beforeService 记录 URI，afterService 根据响应状态决定是否学习
    private static final ThreadLocal<String> PENDING_REQUEST_URI = new ThreadLocal<>();

    public static void beforeService(Object req) {
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
            AlertLogger.debug("[TemporalGuard] beforeService URI: " + uri);
        } catch (Exception e) {
            AlertLogger.debug("[TemporalGuard] beforeService 失败: " + e.getMessage());
        }
    }

    public static void afterService(Object req, Object res) {
        String uri = PENDING_REQUEST_URI.get();
        PENDING_REQUEST_URI.remove();
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
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, null);
            
            if (anomalyScore >= HIGH_RISK_THRESHOLD) {
                block("高风险反射调用: 分数=" + anomalyScore + ", 方法=" + fullSignature, stack);
            } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
                alarm("中风险反射调用: 分数=" + anomalyScore + ", 方法=" + fullSignature, stack);
            }
        }
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

        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险命令执行: 分数=" + anomalyScore + ", 命令=" + command, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险命令执行: 分数=" + anomalyScore + ", 命令=" + command, stack);
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
        int score = 0;

        // 最高风险：系统凭据文件和密钥
        String[] criticalFiles = {
            "/etc/passwd", "/etc/shadow", "id_rsa", "authorized_keys",
            ".keystore", ".truststore", ".jks", ".p12", ".pfx"
        };
        for (String kw : criticalFiles) {
            if (lowerPath.contains(kw)) {
                AlertLogger.alarm("[SensitiveFile] 高风险文件访问: " + filePath);
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
                AlertLogger.alarm("[SensitiveFile] 高风险配置访问: " + filePath);
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
        String[] mediumRiskFiles = {
            "application.properties", "application.yml", "logback.xml",
            "log4j", "jdbc.properties", "mysql", "postgres", "redis",
            "rabbitmq", "kafka", "nacos", "consul"
        };
        for (String kw : mediumRiskFiles) {
            if (lowerPath.contains(kw)) {
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

    private static void block(String reason, StackTraceElement[] stack) {
        com.defense.rasp.agent.AgentConfig.BlockMode mode = 
                com.defense.rasp.agent.AgentConfig.getBlockMode();
        
        if (mode == com.defense.rasp.agent.AgentConfig.BlockMode.BLOCK) {
            AlertLogger.block("[TemporalGuard] " + reason);
            AlertLogger.error("[TemporalGuard] 调用栈:\n" + formatStack(stack));
            throw new SecurityException("[TemporalGuard] 阻断异常调用: " + reason);
        } else {
            AlertLogger.alarm("[MONITOR-ONLY] " + reason + " (仅告警模式)");
        }
    }

    private static void alarm(String reason, StackTraceElement[] stack) {
        AlertLogger.alarm("[TemporalGuard] " + reason);
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
