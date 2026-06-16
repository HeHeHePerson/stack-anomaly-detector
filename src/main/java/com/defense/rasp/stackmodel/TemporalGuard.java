package com.defense.rasp.stackmodel;

import java.nio.file.Path;

/**
 * 统一检测入口：整合所有时空模型进行判定
 * 新增：通过 RaspSecurityManager 拦截文件 I/O
 */
public class TemporalGuard {

    private static final int HIGH_RISK_THRESHOLD = 50;
    private static final int MEDIUM_RISK_THRESHOLD = 20;

    /**
     * 判断是否为 JVM 内部系统调用
     * 如果调用栈表明是 JVM 内部行为（如 PostVMInitHook、Launcher 等），则跳过检测
     * 避免系统启动行为污染正常业务基线
     */
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

    /**
     * 目录列举检测入口
     */
    public static void onFileList(java.io.File dir) {
        if (dir == null) return;
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        if (isSystemInternalCall(stack)) return;
        
        String dirPath = dir.getAbsolutePath();
        AlertLogger.info("[TemporalGuard] 目录列举检测触发: " + dirPath);
        recordThreadEvent("java.io.FileSystem.list", StackTemporalEngine.CallEvent.EventType.ENTER);
        
        long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
        boolean isStartup = jvmUptime < 120_000;
        
        BaselineLearningEngine.learnNormalStack(stack, isStartup);
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

    /**
     * NIO Path 读取检测入口 (ASM Hook 调用)
     */
    public static void onPathRead(Path path) {
        if (path != null) onFileRead(path.toString());
    }

    /**
     * NIO Path 写入检测入口 (ASM Hook 调用)
     */
    public static void onPathWrite(Path path) {
        if (path != null) onFileWrite(path.toString());
    }

    /**
     * NIO Path 删除检测入口 (ASM Hook 调用)
     */
    public static void onPathDelete(Path path) {
        if (path != null) onFileDelete(path.toString());
    }

    /**
     * 文件读取检测入口（SecurityManager/ASM 调用）
     */
    public static void onFileRead(String filePath) {
        if (filePath == null) return;
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        if (isSystemInternalCall(stack)) return;

        AlertLogger.info("[TemporalGuard] 文件读取检测触发: " + filePath);
        recordThreadEvent("java.io.FileInputStream.<init>", StackTemporalEngine.CallEvent.EventType.ENTER);
        
        long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
        boolean isStartup = jvmUptime < 120_000;

        BaselineLearningEngine.learnNormalStack(stack, isStartup);
        int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, filePath);
        if (isSensitiveFile(filePath)) anomalyScore += 20;

        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险时空异常: 分数=" + anomalyScore + ", 文件=" + filePath, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险时空异常: 分数=" + anomalyScore + ", 文件=" + filePath, stack);
        }
    }

    /**
     * 文件写入检测入口（SecurityManager checkWrite 调用）
     */
    public static void onFileWrite(String filePath) {
        if (filePath == null) return;
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        if (isSystemInternalCall(stack)) return;

        AlertLogger.info("[RaspSecurityManager] 文件写入拦截: " + filePath);
        recordThreadEvent("java.io.FileOutputStream.<init>", StackTemporalEngine.CallEvent.EventType.ENTER);
        
        BaselineLearningEngine.learnNormalStack(stack, false);
        int score = BaselineLearningEngine.detectAnomaly(stack, filePath);
        if (isSensitiveFile(filePath)) score += 20;
        
        if (score >= HIGH_RISK_THRESHOLD) {
            block("高风险文件写入: 分数=" + score + ", 文件=" + filePath, stack);
        } else if (score >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险文件写入: 分数=" + score + ", 文件=" + filePath, stack);
        }
    }

    /**
     * 文件删除检测入口（SecurityManager checkDelete 调用）
     */
    public static void onFileDelete(String filePath) {
        if (filePath == null) return;
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        if (isSystemInternalCall(stack)) return;

        AlertLogger.info("[RaspSecurityManager] 文件删除拦截: " + filePath);
        recordThreadEvent("java.io.File.delete", StackTemporalEngine.CallEvent.EventType.ENTER);
        
        BaselineLearningEngine.learnNormalStack(stack, false);
        int score = BaselineLearningEngine.detectAnomaly(stack, filePath);
        if (isSensitiveFile(filePath)) score += 30;
        
        if (score >= HIGH_RISK_THRESHOLD) {
            block("高风险文件删除: 分数=" + score + ", 文件=" + filePath, stack);
        } else if (score >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险文件删除: 分数=" + score + ", 文件=" + filePath, stack);
        }
    }

    /**
     * HTTP 请求检测入口 (ASM Hook HttpServlet.service 调用)
     * 使用 Object 参数避免 SecurityManager 下类加载失败
     */
    public static void onHttpServlet(Object req) {
        if (req == null) return;
        try {
            java.lang.reflect.Method m = req.getClass().getMethod("getRequestURI");
            String uri = (String) m.invoke(req);
            AlertLogger.info("[TemporalGuard] HTTP 请求: " + uri);
            recordThreadEvent("HttpServlet.service", StackTemporalEngine.CallEvent.EventType.ENTER);
            
            long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
            BaselineLearningEngine.learnNormalStack(Thread.currentThread().getStackTrace(), jvmUptime < 120_000);
        } catch (Exception e) {
            // 反射失败不影响正常请求
        }
    }

    /**
     * ServletContext 访问检测
     */
    public static void onServletContextAccess(String path) {
        if (path != null) {
            AlertLogger.info("[TemporalGuard] ServletContext 访问: " + path);
            recordThreadEvent("ServletContext." + path, StackTemporalEngine.CallEvent.EventType.ENTER);
        }
    }

    /**
     * 反射调用检测入口
     */
    public static void onReflectInvoke(String[] methodInfo) {
        if (methodInfo == null || methodInfo.length != 2) return;
        
        String fullSignature = methodInfo[0] + "." + methodInfo[1];
        AlertLogger.info("[TemporalGuard] 反射调用检测触发：" + fullSignature);
        recordThreadEvent(fullSignature, StackTemporalEngine.CallEvent.EventType.ENTER);
        
        if (isSensitiveReflectCall(methodInfo[0], methodInfo[1])) {
            AlertLogger.alarm("[ReflectDetector] 检测到敏感方法的反射调用：" + fullSignature);
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, null);
            
            if (anomalyScore >= HIGH_RISK_THRESHOLD) {
                block("高风险反射调用：分数=" + anomalyScore + ", 方法=" + fullSignature, stack);
            } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
                alarm("中风险反射调用：分数=" + anomalyScore + ", 方法=" + fullSignature, stack);
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

    /**
     * 命令执行检测入口
     */
    public static void onCommandExec(String command) {
        if (command == null || command.isEmpty()) return;
        AlertLogger.info("[TemporalGuard] 命令执行检测触发: " + command);
        
        long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
        boolean isStartup = jvmUptime < 120_000;
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();

        BaselineLearningEngine.learnNormalStack(stack, isStartup);
        int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, null) + analyzeCommand(command);

        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险命令执行: 分数=" + anomalyScore + ", 命令=" + command, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险命令执行: 分数=" + anomalyScore + ", 命令=" + command, stack);
        }
    }
    
    /**
     * ProcessBuilder.start() 检测
     */
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

    private static boolean isSensitiveFile(String filePath) {
        if (filePath == null) return false;
        String lowerPath = filePath.toLowerCase();
        
        String[] keywords = {
            "tomcat-users.xml", "server.xml", "web.xml", "context.xml", "catalina.properties",
            "application.properties", "application.yml", "logback.xml", "log4j", "jdbc.properties",
            ".keystore", ".truststore", ".jks", ".p12", ".pfx", ".key", ".pem", "id_rsa",
            "authorized_keys", ".ssh/", ".env", "/etc/passwd", "/etc/shadow",
            "mysql", "postgres", "redis", "rabbitmq", "kafka", "nacos", "consul"
        };
        
        for (String kw : keywords) {
            if (lowerPath.contains(kw)) {
                AlertLogger.alarm("[SensitiveFile] 敏感文件访问: " + filePath);
                return true;
            }
        }
        
        if ((lowerPath.contains("config") || lowerPath.contains("conf")) && 
            (lowerPath.endsWith(".properties") || lowerPath.endsWith(".xml") ||
             lowerPath.endsWith(".yml") || lowerPath.endsWith(".yaml") ||
             lowerPath.endsWith(".conf"))) {
            return true;
        }
        
        return false;
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

    private static void AlarmWithDetail(String message) {
        AlertLogger.alarm(message);
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
